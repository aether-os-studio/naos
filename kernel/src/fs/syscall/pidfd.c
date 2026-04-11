#include <init/callbacks.h>
#include <fs/fs_syscall.h>
#include <libs/hashmap.h>
#include <task/task.h>

#define PIDFDFS_MAGIC 0x70696466ULL

typedef struct pidfd_ctx {
    uint64_t pid;
    uint64_t exit_status;
    bool exited;
    vfs_node_t *node;
    struct llist_header watch_node;
} pidfd_ctx_t;

typedef struct pidfd_watch_bucket {
    uint64_t key;
    size_t count;
    struct llist_header watchers;
} pidfd_watch_bucket_t;

typedef struct pidfdfs_info {
    spinlock_t lock;
    ino64_t next_ino;
} pidfdfs_info_t;

static hashmap_t pidfd_watch_map = HASHMAP_INIT;
static spinlock_t pidfd_watch_lock = SPIN_INIT;
static struct vfs_file_system_type pidfdfs_fs_type;
static const struct vfs_super_operations pidfdfs_super_ops;
static const struct vfs_file_operations pidfdfs_dir_file_ops;
static const struct vfs_file_operations pidfdfs_file_ops;
static mutex_t pidfdfs_mount_lock;
static struct vfs_mount *pidfdfs_internal_mnt;

static inline pidfd_watch_bucket_t *pidfd_watch_bucket_lookup(uint64_t pid) {
    return (pidfd_watch_bucket_t *)hashmap_get(&pidfd_watch_map, pid);
}

static inline pidfdfs_info_t *pidfdfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (pidfdfs_info_t *)sb->s_fs_info : NULL;
}

static pidfd_ctx_t *pidfd_file_ctx(struct vfs_file *file) {
    if (!file || !file->f_inode || !file->f_inode->i_sb ||
        !file->f_inode->i_sb->s_type ||
        file->f_inode->i_sb->s_type != &pidfdfs_fs_type) {
        return NULL;
    }

    if (file->private_data)
        return (pidfd_ctx_t *)file->private_data;
    return (pidfd_ctx_t *)file->f_inode->i_private;
}

static pidfd_watch_bucket_t *pidfd_watch_bucket_get_or_create(uint64_t pid) {
    pidfd_watch_bucket_t *bucket = pidfd_watch_bucket_lookup(pid);

    if (bucket)
        return bucket;

    bucket = calloc(1, sizeof(*bucket));
    if (!bucket)
        return NULL;

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

    if (!bucket || bucket->count || !llist_empty(&bucket->watchers))
        return;

    hashmap_remove(&pidfd_watch_map, pid);
    free(bucket);
}

static void pidfd_watch_attach_locked(pidfd_ctx_t *ctx) {
    pidfd_watch_bucket_t *bucket;

    if (!ctx || !ctx->pid || !llist_empty(&ctx->watch_node))
        return;

    bucket = pidfd_watch_bucket_get_or_create(ctx->pid);
    if (!bucket)
        return;

    llist_append(&bucket->watchers, &ctx->watch_node);
    bucket->count++;
}

static void pidfd_watch_detach_locked(pidfd_ctx_t *ctx) {
    pidfd_watch_bucket_t *bucket;

    if (!ctx || !ctx->pid || llist_empty(&ctx->watch_node))
        return;

    bucket = pidfd_watch_bucket_lookup(ctx->pid);
    llist_delete(&ctx->watch_node);
    if (bucket && bucket->count)
        bucket->count--;
    pidfd_watch_bucket_destroy_if_empty(ctx->pid);
}

static ssize_t pidfd_read(struct vfs_file *file, void *buf, size_t count,
                          loff_t *ppos) {
    (void)file;
    (void)buf;
    (void)count;
    (void)ppos;
    return -EINVAL;
}

static ssize_t pidfd_write(struct vfs_file *file, const void *buf, size_t count,
                           loff_t *ppos) {
    (void)file;
    (void)buf;
    (void)count;
    (void)ppos;
    return -EINVAL;
}

static __poll_t pidfd_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    pidfd_ctx_t *ctx = pidfd_file_ctx(file);
    task_t *task;

    (void)pt;
    if (!ctx)
        return EPOLLNVAL;

    if (!ctx->exited) {
        task = task_find_by_pid(ctx->pid);
        if (!task || task->state == TASK_DIED) {
            ctx->exited = true;
            if (task)
                ctx->exit_status = task->status;
        }
    }

    return ctx->exited ? EPOLLIN : 0;
}

static long pidfd_ioctl(struct vfs_file *file, unsigned long cmd,
                        unsigned long arg) {
    pidfd_ctx_t *ctx = pidfd_file_ctx(file);
    task_t *task;

    if (!ctx)
        return -EINVAL;

    task = task_find_by_pid(ctx->pid);
    if (!task)
        return -ESRCH;

    switch (cmd) {
    case PIDFD_GET_INFO: {
        pidfd_info_t info;
        if (copy_from_user(&info, (const void *)arg, sizeof(info)))
            return -EFAULT;
        if (info.mask & PIDFD_INFO_PID) {
            info.pid = task->pid;
            info.tgid = task->tgid;
            info.ppid = task->parent ? task->parent->pid : 0;
        }
        if (info.mask & PIDFD_INFO_CGROUPID)
            info.cgroupid = 0;
        if (info.mask & PIDFD_INFO_CREDS) {
            info.ruid = task->uid;
            info.rgid = task->gid;
            info.euid = task->euid;
            info.egid = task->egid;
            info.suid = task->suid;
            info.sgid = task->sgid;
            info.fsuid = task->uid;
            info.fsgid = task->gid;
        }
        info.exit_code = ctx->exited ? ctx->exit_status : 0;
        info.coredump_mask = 0;
        if (copy_to_user((void *)arg, &info, sizeof(info)))
            return -EFAULT;
        return 0;
    }
    default:
        printk("Unsupported pidfd ioctl %#018lx", cmd);
        return -ENOTTY;
    }
}

static int pidfd_release(struct vfs_inode *inode, struct vfs_file *file) {
    pidfd_ctx_t *ctx = pidfd_file_ctx(file);

    (void)inode;
    if (!ctx)
        return 0;

    spin_lock(&pidfd_watch_lock);
    pidfd_watch_detach_locked(ctx);
    spin_unlock(&pidfd_watch_lock);

    free(ctx);

    file->private_data = NULL;
    if (file->f_inode)
        file->f_inode->i_private = NULL;
    return 0;
}

static size_t pidfd_procfs_fdinfo_render(fd_t *fd, char *buf, size_t size) {
    pidfd_ctx_t *ctx;
    int len;

    if (!fd || !fd->node || !buf || size == 0)
        return 0;

    ctx = (pidfd_ctx_t *)(fd->private_data ? fd->private_data
                                           : fd->node->i_private);
    if (!ctx)
        return 0;

    len = snprintf(buf, size, "Pid:\t%llu\nNSpid:\t%llu\n",
                   (unsigned long long)ctx->pid, (unsigned long long)ctx->pid);
    if (len < 0)
        return 0;
    if ((size_t)len >= size)
        return size - 1;
    return (size_t)len;
}

static loff_t pidfd_llseek(struct vfs_file *file, loff_t offset, int whence) {
    (void)file;
    (void)offset;
    (void)whence;
    return -ESPIPE;
}

static int pidfd_open_file(struct vfs_inode *inode, struct vfs_file *file) {
    if (!file)
        return -EINVAL;
    file->private_data = inode ? inode->i_private : NULL;
    return 0;
}

static const struct vfs_file_operations pidfdfs_dir_file_ops = {
    .llseek = pidfd_llseek,
};

static const struct vfs_file_operations pidfdfs_file_ops = {
    .llseek = pidfd_llseek,
    .read = pidfd_read,
    .write = pidfd_write,
    .unlocked_ioctl = pidfd_ioctl,
    .poll = pidfd_poll,
    .open = pidfd_open_file,
    .release = pidfd_release,
    .show_fdinfo = pidfd_procfs_fdinfo_render,
};

static struct vfs_mount *pidfdfs_get_internal_mount(void) {
    int ret;

    mutex_lock(&pidfdfs_mount_lock);
    if (!pidfdfs_internal_mnt) {
        ret = vfs_kern_mount("pidfdfs", 0, NULL, NULL, &pidfdfs_internal_mnt);
        if (ret < 0)
            pidfdfs_internal_mnt = NULL;
    }
    if (pidfdfs_internal_mnt)
        vfs_mntget(pidfdfs_internal_mnt);
    mutex_unlock(&pidfdfs_mount_lock);
    return pidfdfs_internal_mnt;
}

static int pidfdfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int pidfdfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    pidfdfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *root;

    if (!fc)
        return -EINVAL;

    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb)
        return -ENOMEM;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    sb->s_magic = PIDFDFS_MAGIC;
    sb->s_fs_info = fsi;
    sb->s_op = &pidfdfs_super_ops;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->inode = 1;
    inode->i_mode = S_IFDIR | 0700;
    inode->type = file_dir;
    inode->i_nlink = 2;
    inode->i_fop = &pidfdfs_dir_file_ops;

    root = vfs_d_alloc(sb, NULL, NULL);
    if (!root) {
        vfs_iput(inode);
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root, inode);
    sb->s_root = root;
    fc->sb = sb;
    return 0;
}

static void pidfdfs_kill_sb(struct vfs_super_block *sb) {
    if (!sb)
        return;
    free(sb->s_fs_info);
    sb->s_fs_info = NULL;
}

static const struct vfs_super_operations pidfdfs_super_ops = {
    .put_super = pidfdfs_kill_sb,
};

static struct vfs_file_system_type pidfdfs_fs_type = {
    .name = "pidfdfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = pidfdfs_init_fs_context,
    .get_tree = pidfdfs_get_tree,
};

static int pidfd_create_handle_file(pidfd_ctx_t *ctx, unsigned int open_flags,
                                    struct vfs_file **out_file) {
    struct vfs_mount *mnt;
    struct vfs_super_block *sb;
    pidfdfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *dentry;
    struct vfs_qstr name = {0};
    struct vfs_file *file;
    char namebuf[32];

    if (!ctx || !out_file)
        return -EINVAL;

    mnt = pidfdfs_get_internal_mount();
    if (!mnt)
        return -ENODEV;

    sb = mnt->mnt_sb;
    fsi = pidfdfs_sb_info(sb);
    inode = vfs_alloc_inode(sb);
    if (!inode) {
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    spin_lock(&fsi->lock);
    inode->i_ino = ++fsi->next_ino;
    spin_unlock(&fsi->lock);
    inode->inode = inode->i_ino;
    inode->i_mode = S_IFCHR | 0600;
    inode->type = file_stream;
    inode->i_nlink = 1;
    inode->i_fop = &pidfdfs_file_ops;
    inode->i_private = ctx;
    ctx->node = inode;

    snprintf(namebuf, sizeof(namebuf), "pidfd-%llu",
             (unsigned long long)inode->i_ino);
    vfs_qstr_make(&name, namebuf);
    dentry = vfs_d_alloc(sb, sb->s_root, &name);
    if (!dentry) {
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    vfs_d_instantiate(dentry, inode);
    file = vfs_alloc_file(&(struct vfs_path){.mnt = mnt, .dentry = dentry},
                          O_RDWR | (open_flags & O_NONBLOCK));
    if (!file) {
        vfs_dput(dentry);
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    file->private_data = ctx;
    *out_file = file;

    vfs_dput(dentry);
    vfs_iput(inode);
    vfs_mntput(mnt);
    return 0;
}

uint64_t pidfd_create_for_pid(uint64_t pid, uint64_t flags, bool cloexec) {
    task_t *target;
    pidfd_ctx_t *ctx;
    struct vfs_file *file = NULL;
    int ret;

    if (!pid)
        return (uint64_t)-EINVAL;
    if (flags & ~PIDFD_NONBLOCK)
        return (uint64_t)-EINVAL;

    target = task_find_by_pid(pid);
    if (!target)
        return (uint64_t)-ESRCH;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return (uint64_t)-ENOMEM;

    ctx->pid = pid;
    ctx->exited = (target->state == TASK_DIED);
    ctx->exit_status = target->status;
    llist_init_head(&ctx->watch_node);

    ret = pidfd_create_handle_file(ctx, (unsigned int)flags, &file);
    if (ret < 0) {
        free(ctx);
        return (uint64_t)ret;
    }

    spin_lock(&pidfd_watch_lock);
    pidfd_watch_attach_locked(ctx);
    spin_unlock(&pidfd_watch_lock);

    ret = task_install_file(current_task, file, cloexec ? FD_CLOEXEC : 0, 0);
    if (ret < 0) {
        spin_lock(&pidfd_watch_lock);
        pidfd_watch_detach_locked(ctx);
        spin_unlock(&pidfd_watch_lock);
    }
    vfs_close_file(file);
    return (uint64_t)ret;
}

uint64_t sys_pidfd_open(int pid, uint64_t flags) {
    if (pid <= 0)
        return (uint64_t)-EINVAL;
    return pidfd_create_for_pid((uint64_t)pid, flags, true);
}

uint64_t sys_pidfd_send_signal(uint64_t pidfd, int sig, siginfo_t *info,
                               uint64_t flags) {
    uint64_t pid = 0;
    task_t *target;

    if (sig < 0 || sig >= MAXSIG)
        return (uint64_t)-EINVAL;
    if (flags != 0)
        return (uint64_t)-EINVAL;

    int ret = pidfd_get_pid_from_fd(pidfd, &pid);
    if (ret < 0)
        return (uint64_t)ret;

    target = task_find_by_pid(pid);
    if (!target)
        return (uint64_t)-ESRCH;

    if (sig == 0)
        return 0;

    if (!info) {
        task_send_signal(target, sig, SI_USER);
        return 0;
    }

    siginfo_t kinfo;
    if (copy_from_user(&kinfo, info, sizeof(kinfo)))
        return (uint64_t)-EFAULT;

    kinfo.si_signo = sig;
    task_commit_signal(target, sig, &kinfo);
    return 0;
}

int pidfd_get_pid_from_fd(uint64_t fd, uint64_t *pid_out) {
    struct vfs_file *file;
    pidfd_ctx_t *ctx;

    if (!pid_out || fd >= MAX_FD_NUM)
        return -EBADF;

    file = task_get_file(current_task, (int)fd);
    if (!file)
        return -EBADF;

    ctx = pidfd_file_ctx(file);
    if (!ctx) {
        vfs_file_put(file);
        return -EBADF;
    }

    *pid_out = ctx->pid;
    vfs_file_put(file);
    return 0;
}

void pidfd_on_task_exit(task_t *task) {
    pidfd_watch_bucket_t *bucket;
    struct llist_header *node;

    if (!task || !task->pid)
        return;

    spin_lock(&pidfd_watch_lock);
    bucket = pidfd_watch_bucket_lookup(task->pid);
    node = bucket ? bucket->watchers.next : NULL;
    while (bucket && node != &bucket->watchers) {
        pidfd_ctx_t *ctx = list_entry(node, pidfd_ctx_t, watch_node);
        node = node->next;
        if (!ctx)
            continue;
        ctx->exited = true;
        ctx->exit_status = task->status;
        if (ctx->node)
            vfs_poll_notify(ctx->node, EPOLLIN);
    }
    spin_unlock(&pidfd_watch_lock);
}

void pidfd_init(void) {
    ASSERT(hashmap_init(&pidfd_watch_map, 128) == 0);
    spin_init(&pidfd_watch_lock);
    mutex_init(&pidfdfs_mount_lock);
    vfs_register_filesystem(&pidfdfs_fs_type);
}
