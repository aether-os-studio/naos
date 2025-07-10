#include <fs/fs_syscall.h>

static int dummy()
{
    return 0;
}

static int signalfd_poll(void *file, size_t event)
{
    struct signalfd_ctx *ctx = file;

    int revents = 0;

    if (ctx->queue_head != ctx->queue_tail)
    {
        revents |= EPOLLIN;
    }

    return revents;
}

static vfs_node_t signalfdfs_root = NULL;
int signalfdfs_id = 0;
int signalfd_id = 0;

static ssize_t signalfd_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    struct signalfd_ctx *ctx = data;

    while (ctx->queue_head == ctx->queue_tail)
    {
#if defined(__x86_64__)
        arch_enable_interrupt();
#endif

        arch_pause();
    }

#if defined(__x86_64__)
    arch_disable_interrupt();
#endif

    struct signalfd_siginfo *ev = &ctx->queue[ctx->queue_tail];
    size_t copy_len = len < sizeof(*ev) ? len : sizeof(*ev);
    memcpy(buf, ev, copy_len);

    ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
    return copy_len;
}

static int signalfd_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    struct signalfd_ctx *ctx = data;
    switch (cmd)
    {
    case SIGNALFD_IOC_MASK:
        memcpy(&ctx->sigmask, (sigset_t *)arg, sizeof(sigset_t));
        return 0;
    default:
        return -ENOTTY;
    }
}

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask, int flags)
{
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
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fds[i])
        {
            fd = i;
            break;
        }
    }

    // 创建VFS节点
    char buf[256];
    sprintf(buf, "signalfd%d", signalfd_id++);
    vfs_node_t node = vfs_node_alloc(signalfdfs_root, buf);
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = signalfdfs_id;
    node->handle = ctx;
    current_task->fds[fd] = malloc(sizeof(fd_t));
    current_task->fds[fd]->node = node;
    current_task->fds[fd]->offset = 0;
    current_task->fds[fd]->flags = 0;

    return fd;
}

uint64_t sys_signalfd(int ufd, const sigset_t *mask, size_t sizemask)
{
    return sys_signalfd4(ufd, mask, sizemask, 0);
}

static struct vfs_callback signalfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)signalfd_read,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)signalfd_ioctl,
    .poll = signalfd_poll,
    .resize = (vfs_resize_t)dummy,
};

void signalfd_init()
{
    signalfdfs_id = vfs_regist("signalfdfs", &signalfd_callbacks);
    signalfdfs_root = vfs_node_alloc(rootdir, "signal");
    signalfdfs_root->type = file_dir;
    signalfdfs_root->mode = 0644;
    signalfdfs_root->fsid = signalfdfs_id;
}
