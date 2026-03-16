#include <init/abis.h>
#include <fs/fs_syscall.h>
#include <fs/proc.h>
#include <libs/hashmap.h>

typedef struct pidfd_ctx {
    uint64_t pid;
    uint64_t exit_status;
    bool exited;
    vfs_node_t node;
    struct llist_header watch_node;
} pidfd_ctx_t;

typedef struct pidfd_watch_bucket {
    uint64_t key;
    size_t count;
    struct llist_header watchers;
} pidfd_watch_bucket_t;

static hashmap_t pidfd_watch_map = HASHMAP_INIT;
static spinlock_t pidfd_watch_lock = SPIN_INIT;
static int pidfdfs_id = 0;

static inline pidfd_watch_bucket_t *pidfd_watch_bucket_lookup(uint64_t pid) {
    return (pidfd_watch_bucket_t *)hashmap_get(&pidfd_watch_map, pid);
}

static pidfd_watch_bucket_t *pidfd_watch_bucket_get_or_create(uint64_t pid) {
    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_lookup(pid);
    if (bucket) {
        return bucket;
    }

    bucket = calloc(1, sizeof(pidfd_watch_bucket_t));
    if (!bucket) {
        return NULL;
    }

    bucket->key = pid;
    llist_init_head(&bucket->watchers);
    if (hashmap_put(&pidfd_watch_map, pid, bucket) != 0) {
        free(bucket);
        return NULL;
    }

    return bucket;
}

static void pidfd_watch_bucket_destroy_if_empty(uint64_t pid) {
    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_lookup(pid);
    if (!bucket || bucket->count || !llist_empty(&bucket->watchers)) {
        return;
    }

    hashmap_remove(&pidfd_watch_map, pid);
    free(bucket);
}

static void pidfd_watch_attach_locked(pidfd_ctx_t *ctx) {
    if (!ctx || !ctx->pid || !llist_empty(&ctx->watch_node)) {
        return;
    }

    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_get_or_create(ctx->pid);
    if (!bucket) {
        return;
    }

    llist_append(&bucket->watchers, &ctx->watch_node);
    bucket->count++;
}

static void pidfd_watch_detach_locked(pidfd_ctx_t *ctx) {
    if (!ctx || !ctx->pid || llist_empty(&ctx->watch_node)) {
        return;
    }

    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_lookup(ctx->pid);
    llist_delete(&ctx->watch_node);

    if (bucket && bucket->count) {
        bucket->count--;
    }

    pidfd_watch_bucket_destroy_if_empty(ctx->pid);
}

static ssize_t pidfd_read(fd_t *fd, void *buf, size_t offset, size_t size) {
    (void)fd;
    (void)buf;
    (void)offset;
    (void)size;
    return -EINVAL;
}

static ssize_t pidfd_write(fd_t *fd, const void *buf, size_t offset,
                           size_t size) {
    (void)fd;
    (void)buf;
    (void)offset;
    (void)size;
    return -EINVAL;
}

static int pidfd_poll(vfs_node_t node, size_t events) {
    pidfd_ctx_t *ctx = node ? node->handle : NULL;
    if (!ctx) {
        return EPOLLNVAL;
    }

    if (!ctx->exited) {
        task_t *task = task_find_by_pid(ctx->pid);
        if (!task || task->state == TASK_DIED) {
            ctx->exited = true;
            if (task) {
                ctx->exit_status = task->status;
            }
        }
    }

    if ((events & EPOLLIN) && ctx->exited) {
        return EPOLLIN;
    }

    return 0;
}

static bool pidfd_close(vfs_node_t node) {
    pidfd_ctx_t *ctx = node ? node->handle : NULL;
    if (!ctx) {
        return true;
    }

    spin_lock(&pidfd_watch_lock);
    pidfd_watch_detach_locked(ctx);
    spin_unlock(&pidfd_watch_lock);

    free(ctx);
    return true;
}

static vfs_operations_t pidfd_callbacks = {
    .close = pidfd_close,
    .read = pidfd_read,
    .write = pidfd_write,
    .poll = pidfd_poll,

    .free_handle = vfs_generic_free_handle,
};

static fs_t pidfdfs = {
    .name = "pidfdfs",
    .magic = 0,
    .ops = &pidfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

uint64_t pidfd_create_for_pid(uint64_t pid, uint64_t flags, bool cloexec) {
    if (!pid) {
        return (uint64_t)-EINVAL;
    }
    if (flags & ~PIDFD_NONBLOCK) {
        return (uint64_t)-EINVAL;
    }

    task_t *target = task_find_by_pid(pid);
    if (!target) {
        return (uint64_t)-ESRCH;
    }

    pidfd_ctx_t *ctx = calloc(1, sizeof(pidfd_ctx_t));
    if (!ctx) {
        return (uint64_t)-ENOMEM;
    }

    ctx->pid = pid;
    ctx->exited = (target->state == TASK_DIED);
    ctx->exit_status = target->status;
    llist_init_head(&ctx->watch_node);

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    if (!node) {
        free(ctx);
        return (uint64_t)-ENOMEM;
    }

    node->refcount++;
    node->owner = current_task->uid;
    node->group = current_task->gid;
    node->mode = 0600;
    node->type = file_stream;
    node->fsid = pidfdfs_id;
    node->rdev = ((uint64_t)pidfdfs_id << 8) | 0;
    node->handle = ctx;
    ctx->node = node;

    spin_lock(&pidfd_watch_lock);
    pidfd_watch_attach_locked(ctx);
    spin_unlock(&pidfd_watch_lock);

    int fd = -1;
    int ret = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (!current_task->fd_info->fds[i]) {
                fd = i;
                break;
            }
        }

        if (fd < 0)
            break;

        fd_t *new_fd = calloc(1, sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        new_fd->node = node;
        new_fd->offset = 0;
        new_fd->flags = O_RDWR | flags;
        new_fd->close_on_exec = cloexec;
        current_task->fd_info->fds[fd] = new_fd;
        system_abi->on_open_file(current_task, fd);
        ret = 0;
    });

    if (ret < 0) {
        spin_lock(&pidfd_watch_lock);
        pidfd_watch_detach_locked(ctx);
        spin_unlock(&pidfd_watch_lock);
        node->handle = NULL;
        vfs_free(node);
        free(ctx);
        return (uint64_t)ret;
    }

    return (uint64_t)fd;
}

uint64_t sys_pidfd_open(int pid, uint64_t flags) {
    if (pid <= 0) {
        return (uint64_t)-EINVAL;
    }

    return pidfd_create_for_pid((uint64_t)pid, flags, true);
}

int pidfd_get_pid_from_fd(uint64_t fd, uint64_t *pid_out) {
    if (!pid_out || fd >= MAX_FD_NUM) {
        return -EBADF;
    }

    fd_t *file = NULL;
    with_fd_info_lock(current_task->fd_info,
                      { file = current_task->fd_info->fds[fd]; });

    if (!file || !file->node || file->node->fsid != pidfdfs_id ||
        !file->node->handle) {
        return -EBADF;
    }

    pidfd_ctx_t *ctx = file->node->handle;
    *pid_out = ctx->pid;
    return 0;
}

void pidfd_on_task_exit(task_t *task) {
    if (!task || !task->pid) {
        return;
    }

    spin_lock(&pidfd_watch_lock);
    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_lookup(task->pid);
    struct llist_header *node = bucket ? bucket->watchers.next : NULL;
    while (bucket && node != &bucket->watchers) {
        pidfd_ctx_t *ctx = list_entry(node, pidfd_ctx_t, watch_node);
        node = node->next;
        if (!ctx) {
            continue;
        }

        ctx->exited = true;
        ctx->exit_status = task->status;
        if (ctx->node) {
            vfs_poll_notify(ctx->node, EPOLLIN);
        }
    }
    spin_unlock(&pidfd_watch_lock);
}

void pidfd_init() {
    ASSERT(hashmap_init(&pidfd_watch_map, 128) == 0);
    spin_init(&pidfd_watch_lock);
    pidfdfs_id = vfs_regist(&pidfdfs);
}
