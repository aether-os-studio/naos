#include <fs/fs_syscall.h>

vfs_node_t eventfdfs_root = NULL;
int eventfdfs_id = 0;

int eventfd_id = 0;

static int dummy()
{
    return -ENOSYS;
}

uint64_t sys_eventfd2(uint64_t initial_val, uint64_t flags)
{
    // 参数校验
    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE))
        return (uint64_t)-EINVAL;

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

    if (fd == -1)
    {
        return (uint64_t)-EMFILE;
    }

    // 分配eventfd结构体
    eventfd_t *efd = malloc(sizeof(eventfd_t));
    if (!efd)
        return (uint64_t)-ENOMEM;

    efd->count = initial_val;
    efd->flags = flags;

    // 创建VFS节点
    char buf[256];
    sprintf(buf, "eventfd%d", eventfd_id++);
    vfs_node_t node = vfs_node_alloc(eventfdfs_root, buf);
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = eventfdfs_id;
    node->handle = efd;

    current_task->fds[fd] = malloc(sizeof(fd_t));
    current_task->fds[fd]->node = node;
    current_task->fds[fd]->offset = 0;
    current_task->fds[fd]->flags = 0;

    return fd;
}

// 实现读写操作
static ssize_t eventfd_read(vfs_node_t node, void *buf, size_t offset, size_t len)
{
    eventfd_t *efd = node->handle;
    uint64_t value;

    while (efd->count == 0)
    {
        if (efd->flags & EFD_NONBLOCK)
            return -EAGAIN;

        arch_enable_interrupt();

        arch_pause();
    }

    value = (efd->flags & EFD_SEMAPHORE) ? 1 : efd->count;
    memcpy(buf, &value, sizeof(uint64_t));

    efd->count -= value;
    return sizeof(uint64_t);
}

static ssize_t eventfd_write(vfs_node_t node, const void *buf, size_t offset, size_t len)
{
    eventfd_t *efd = node->handle;
    uint64_t value;
    memcpy(&value, buf, sizeof(uint64_t));

    if (UINT64_MAX - efd->count < value)
        return -EINVAL;

    efd->count += value;

    return sizeof(uint64_t);
}

static int eventfd_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

static struct vfs_callback eventfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)eventfd_read,
    .write = (vfs_write_t)eventfd_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = eventfd_poll,
};

void eventfd_init()
{
    eventfdfs_id = vfs_regist("eventfdfs", &eventfd_callbacks);
    eventfdfs_root = vfs_node_alloc(rootdir, "event");
    eventfdfs_root->type = file_dir;
    eventfdfs_root->mode = 0644;
    eventfdfs_root->fsid = eventfdfs_id;
}
