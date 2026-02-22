#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>

static int dummy() { return 0; }

static int signalfd_poll(vfs_node_t node, size_t event) {
    struct signalfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return EPOLLNVAL;

    int revents = 0;

    if (ctx->queue_head != ctx->queue_tail) {
        revents |= EPOLLIN;
    }

    return revents;
}

int signalfdfs_id = 0;
int signalfd_id = 0;

static ssize_t signalfd_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *data = fd->node->handle;

    struct signalfd_ctx *ctx = data;

    while (ctx->queue_head == ctx->queue_tail) {
        if (fd->flags & O_NONBLOCK)
            return -EWOULDBLOCK;
        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
        vfs_poll_wait_arm(fd->node, &wait);
        if (ctx->queue_head == ctx->queue_tail) {
            int reason =
                task_block(current_task, TASK_BLOCKING, -1, "signalfd_read");
            vfs_poll_wait_disarm(&wait);
            if (reason != EOK)
                return -EINTR;
        } else {
            vfs_poll_wait_disarm(&wait);
        }
    }

    struct signalfd_siginfo *ev = &ctx->queue[ctx->queue_tail];
    size_t copy_len = size < sizeof(*ev) ? size : sizeof(*ev);
    memcpy(addr, ev, copy_len);
    ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
    return copy_len;
}

static int signalfd_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    struct signalfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return -EBADF;
    switch (cmd) {
    case SIGNALFD_IOC_MASK:
        memcpy(&ctx->sigmask, (sigset_t *)arg, sizeof(sigset_t));
        return 0;
    default:
        return -ENOTTY;
    }
}

bool signalfd_close(vfs_node_t node) {
    struct signalfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return true;
    if (ctx->queue)
        free(ctx->queue);
    free(ctx);
    return true;
}

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask,
                       int flags) {
    if (sizemask < sizeof(uint32_t) || sizemask > sizeof(uint64_t)) {
        return -EINVAL;
    }

    struct signalfd_ctx *ctx = malloc(sizeof(struct signalfd_ctx));
    if (!ctx)
        return -ENOMEM;

    if (copy_from_user(&ctx->sigmask, mask, sizemask)) {
        free(ctx);
        return (uint64_t)-EFAULT;
    }

    ctx->queue_size = 64;
    ctx->queue = calloc(ctx->queue_size, sizeof(struct signalfd_siginfo));
    if (!ctx->queue) {
        free(ctx);
        return -ENOMEM;
    }
    ctx->queue_head = ctx->queue_tail = 0;

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
        new_fd->offset = 0;
        new_fd->flags = flags;
        current_task->fd_info->fds[fd] = new_fd;
        procfs_on_open_file(current_task, fd);
        ret = 0;
    });

    if (ret < 0) {
        node->handle = NULL;
        vfs_free(node);
        free(ctx->queue);
        free(ctx);
        return ret;
    }

    return fd;
}

uint64_t sys_signalfd(int ufd, const sigset_t *mask, size_t sizemask) {
    return sys_signalfd4(ufd, mask, sizemask, 0);
}

static vfs_operations_t signalfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .remount = (vfs_remount_t)dummy,
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
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)signalfd_ioctl,
    .poll = signalfd_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t signalfdfs = {
    .name = "signalfdfs",
    .magic = 0,
    .ops = &signalfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void signalfd_init() { signalfdfs_id = vfs_regist(&signalfdfs); }
