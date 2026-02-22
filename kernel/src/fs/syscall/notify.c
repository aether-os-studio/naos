#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

static int notifyfs_id = 0;

static int watch_desc = 1;

struct llist_header all_watches;
spinlock_t all_watches_lock = SPIN_INIT;

struct inotify_event {
    int wd;
    unsigned int mask;
    unsigned int cookie;
    unsigned int len;
    char name[];
};

ssize_t notifyfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    notifyfs_handle_t *handle = fd->node->handle;
    if (!handle)
        return -EINVAL;

    struct inotify_event *write_pos = (struct inotify_event *)addr;

    uint64_t total_write = 0;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        struct vfs_notify_event *p, *t;
        llist_for_each(p, t, &pos->events, node) {
            int str_len = strlen(p->changed_node->name) + 1;
            int tot_len = str_len + sizeof(struct inotify_event);
            if ((uint64_t)write_pos - (uint64_t)addr + tot_len > size)
                break;
            llist_delete(&p->node);
            write_pos->wd = pos->wd;
            write_pos->mask = p->mask;
            write_pos->cookie = 0;
            write_pos->len = str_len;
            memcpy(write_pos->name, p->changed_node->name, str_len + 1);
            total_write += tot_len;
        }
    }

    return total_write ?: -EWOULDBLOCK;
}

static int notifyfs_poll(vfs_node_t node, size_t events) {
    int revents = 0;

    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return EPOLLNVAL;
    notifyfs_watch_t *pos, *tmp;
    if (events & EPOLLIN) {
        llist_for_each(pos, tmp, &handle->watches, node) {
            int event_count = 0;
            struct vfs_notify_event *p, *t;
            llist_for_each(p, t, &pos->events, node) { event_count++; }
            if (event_count > 0) {
                revents |= EPOLLIN;
                break;
            }
        }
    }

    return revents;
}

static bool notifyfs_close(vfs_node_t node) {
    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return true;
    handle->node->flags |= VFS_NODE_FLAGS_DELETED;
    return true;
}

static vfs_operations_t notifyfs_callbacks = {
    .close = notifyfs_close,
    .read = notifyfs_read,
    .poll = notifyfs_poll,

    .free_handle = vfs_generic_free_handle,
};

fs_t notifyfs_fs = {
    .name = "notifyfs",
    .magic = 0,
    .ops = &notifyfs_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

uint64_t sys_inotify_init1(uint64_t flags) {
    if (flags & ~(O_NONBLOCK | O_CLOEXEC))
        return (uint64_t)-EINVAL;

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->type = file_none;
    node->fsid = notifyfs_id;
    node->refcount++;
    node->size = 0;
    notifyfs_handle_t *handle = malloc(sizeof(notifyfs_handle_t));
    node->handle = handle;
    handle->node = node;
    llist_init_head(&handle->watches);

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

        fd_t *new_fd = malloc(sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        memset(new_fd, 0, sizeof(fd_t));
        new_fd->node = node;
        new_fd->flags = flags & ~(uint64_t)O_CLOEXEC;
        new_fd->close_on_exec = !!(flags & O_CLOEXEC);
        current_task->fd_info->fds[fd] = new_fd;
        procfs_on_open_file(current_task, fd);
        ret = 0;
    });

    if (ret < 0) {
        vfs_free(node);
        return (uint64_t)ret;
    }

    return fd;
}

uint64_t sys_inotify_init() { return sys_inotify_init1(0); }

uint64_t sys_inotify_add_watch(uint64_t notifyfd, const char *path_user,
                               uint64_t mask) {
    if (notifyfd == SPECIAL_FD)
        return 0;

    if (notifyfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[notifyfd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t notify_node = current_task->fd_info->fds[notifyfd]->node;
    if (notify_node->fsid != notifyfs_id) {
        return (uint64_t)-EINVAL;
    }
    notifyfs_handle_t *handle = notify_node->handle;
    if (!handle) {
        return -EINVAL;
    }

    char path[256];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    vfs_node_t node = vfs_open(path, O_NOFOLLOW);
    if (!node)
        return (uint64_t)-ENOENT;
    node = vfs_get_real_node(node);
    if (!node)
        return (uint64_t)-ENOENT;

    node->refcount++;

    spin_lock(&all_watches_lock);

    notifyfs_watch_t *watch = malloc(sizeof(notifyfs_watch_t));
    watch->watch_node = node;
    watch->owner = handle;
    watch->wd = watch_desc++;
    watch->mask = mask;

    llist_init_head(&watch->node);
    llist_prepend(&handle->watches, &watch->node);

    spin_init(&watch->events_lock);
    llist_init_head(&watch->events);

    llist_init_head(&watch->all_watches_node);
    llist_prepend(&all_watches, &watch->all_watches_node);

    spin_unlock(&all_watches_lock);

    return watch->wd;
}

uint64_t sys_inotify_rm_watch(uint64_t watchdesc, uint64_t mask) {
    spin_lock(&all_watches_lock);

    notifyfs_watch_t *watch = NULL;
    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &all_watches, all_watches_node) {
        if (pos->wd == watchdesc) {
            watch = pos;
            break;
        }
    }

    if (!watch) {
        spin_unlock(&all_watches_lock);
        return (uint64_t)-EBADF;
    }

    vfs_close(watch->watch_node);
    llist_delete(&watch->node);
    llist_delete(&watch->all_watches_node);
    struct vfs_notify_event *p, *t;
    llist_for_each(p, t, &watch->events, node) {
        llist_delete(&p->node);
        free(p);
    }
    free(watch);

    spin_unlock(&all_watches_lock);

    return 0;
}

bool notifyfs_initialized = false;

void notifyfs_init() {
    llist_init_head(&all_watches);
    notifyfs_id = vfs_regist(&notifyfs_fs);
    notifyfs_initialized = true;
}
