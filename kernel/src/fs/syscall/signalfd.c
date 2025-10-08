#include <fs/fs_syscall.h>

static int dummy() { return 0; }

static int signalfd_poll(void *file, size_t event) {
    struct signalfd_ctx *ctx = file;

    int revents = 0;

    if (ctx->queue_head != ctx->queue_tail) {
        revents |= EPOLLIN;
    }

    return revents;
}

int signalfdfs_id = 0;
int signalfd_id = 0;

static ssize_t signalfd_read(fd_t *fd, uint64_t offset, void *buf,
                             uint64_t len) {
    void *data = fd->node->handle;

    struct signalfd_ctx *ctx = data;

    while (ctx->queue_head == ctx->queue_tail) {
        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

    struct signalfd_siginfo *ev = &ctx->queue[ctx->queue_tail];
    size_t copy_len = len < sizeof(*ev) ? len : sizeof(*ev);
    memcpy(buf, ev, copy_len);

    ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
    return copy_len;
}

static int signalfd_ioctl(void *data, ssize_t cmd, ssize_t arg) {
    struct signalfd_ctx *ctx = data;
    switch (cmd) {
    case SIGNALFD_IOC_MASK:
        memcpy(&ctx->sigmask, (sigset_t *)arg, sizeof(sigset_t));
        return 0;
    default:
        return -ENOTTY;
    }
}

bool signalfd_close(void *handle) {
    struct signalfd_ctx *ctx = handle;
    free(ctx->node->name);
    free(ctx->node);
    free(ctx);
    return true;
}

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask,
                       int flags) {
    if (sizemask != sizeof(sigset_t))
        return -EINVAL;

    struct signalfd_ctx *ctx = malloc(sizeof(struct signalfd_ctx));
    if (!ctx)
        return -ENOMEM;

    memcpy(&ctx->sigmask, mask, sizeof(sigset_t));

    ctx->queue_size = 32;
    ctx->queue = malloc(ctx->queue_size * sizeof(struct sigevent));
    ctx->queue_head = ctx->queue_tail = 0;

    // 分配文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            fd = i;
            break;
        }
    }

    // 创建VFS节点
    char buf[256];
    sprintf(buf, "signalfd%d", signalfd_id++);
    vfs_node_t node = vfs_node_alloc(NULL, buf);
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = signalfdfs_id;
    node->handle = ctx;
    ctx->node = node;
    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->offset = 0;
    current_task->fd_info->fds[fd]->flags = 0;

    return fd;
}

uint64_t sys_signalfd(int ufd, const sigset_t *mask, size_t sizemask) {
    return sys_signalfd4(ufd, mask, sizemask, 0);
}

static struct vfs_callback signalfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)signalfd_close,
    .read = (vfs_read_t)signalfd_read,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)signalfd_ioctl,
    .poll = signalfd_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,

    .free_handle = vfs_generic_free_handle,
};

fs_t signalfdfs = {
    .name = "signalfdfs",
    .magic = 0,
    .callback = &signalfd_callbacks,
};

void signalfd_init() { signalfdfs_id = vfs_regist(&signalfdfs); }
