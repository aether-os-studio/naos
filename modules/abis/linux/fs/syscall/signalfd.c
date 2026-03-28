#include <fs/fs_syscall.h>
#include <fs/proc.h>
#include <task/signal.h>
#include <init/callbacks.h>

static inline void signalfd_apply_flags(fd_t *fd, int flags) {
    uint64_t file_flags = fd_get_flags(fd);
    file_flags &= ~O_NONBLOCK;
    if (flags & O_NONBLOCK) {
        file_flags |= O_NONBLOCK;
    }
    fd_set_flags(fd, file_flags);
    fd->close_on_exec = !!(flags & O_CLOEXEC);
}

static int signalfd_poll(vfs_node_t *node, size_t event) {
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
        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;
        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
        vfs_poll_wait_arm(fd->node, &wait);
        if (ctx->queue_head == ctx->queue_tail) {
            int reason =
                vfs_poll_wait_sleep(fd->node, &wait, -1, "signalfd_read");
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

static int signalfd_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    vfs_node_t *node = fd->node;
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

bool signalfd_close(vfs_node_t *node) {
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
    if (ufd < -1) {
        return -EINVAL;
    }
    if (!signal_sigset_size_valid(sizemask)) {
        return -EINVAL;
    }
    if (flags & ~(O_NONBLOCK | O_CLOEXEC)) {
        return -EINVAL;
    }

    sigset_t sigmask = 0;
    if (copy_from_user(&sigmask, mask, sizemask)) {
        return (uint64_t)-EFAULT;
    }

    if (ufd >= 0) {
        uint64_t ret = (uint64_t)-EBADF;

        with_fd_info_lock(current_task->fd_info, {
            if (ufd >= MAX_FD_NUM || !current_task->fd_info->fds[ufd]) {
                break;
            }

            fd_t *fd = current_task->fd_info->fds[ufd];
            if (!fd->node || fd->node->fsid != signalfdfs_id ||
                !fd->node->handle) {
                ret = (uint64_t)-EINVAL;
                break;
            }

            struct signalfd_ctx *ctx = fd->node->handle;
            ctx->sigmask = sigmask;
            signalfd_apply_flags(fd, flags);
            ret = (uint64_t)ufd;
        });

        return ret;
    }

    struct signalfd_ctx *ctx = malloc(sizeof(struct signalfd_ctx));
    if (!ctx)
        return -ENOMEM;
    memset(ctx, 0, sizeof(*ctx));
    ctx->sigmask = sigmask;

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
    vfs_node_t *node = vfs_node_alloc(NULL, buf);
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = signalfdfs_id;
    node->handle = ctx;
    node->flags |= VFS_NODE_FLAGS_FREE_AFTER_USE;
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

        fd_t *new_fd = fd_create(node, O_RDONLY | (flags & O_NONBLOCK),
                                 !!(flags & O_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        current_task->fd_info->fds[fd] = new_fd;
        on_open_file_call(current_task, fd);
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
    .close = signalfd_close,
    .read = signalfd_read,
    .ioctl = signalfd_ioctl,
    .poll = signalfd_poll,

    .free_handle = vfs_generic_free_handle,
};

fs_t signalfdfs = {
    .name = "signalfdfs",
    .magic = 0,
    .ops = &signalfd_callbacks,
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_HIDDEN,
};

void signalfd_init() { signalfdfs_id = vfs_regist(&signalfdfs); }
