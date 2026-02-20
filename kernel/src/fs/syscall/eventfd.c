#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>

int eventfdfs_id = 0;

static int dummy() { return 0; }

uint64_t sys_eventfd2(uint64_t initial_val, uint64_t flags) {
    // 参数校验
    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE))
        return (uint64_t)-EINVAL;

    // 分配eventfd结构体
    eventfd_t *efd = malloc(sizeof(eventfd_t));
    if (!efd)
        return (uint64_t)-ENOMEM;

    efd->count = initial_val;
    efd->flags = flags;

    // 创建VFS节点
    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = eventfdfs_id;
    node->handle = efd;

    efd->node = node;

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
        new_fd->flags = O_RDWR | flags;
        new_fd->close_on_exec = !!(flags & EFD_CLOEXEC);
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

// 实现读写操作
static ssize_t eventfd_read(fd_t *fd, void *buf, size_t offset, size_t len) {
    eventfd_t *efd = fd->node->handle;

    uint64_t value;

    while (efd->count == 0) {
        if (efd->flags & EFD_NONBLOCK)
            return -EAGAIN;

        schedule(SCHED_FLAG_YIELD);
    }

    value = (efd->flags & EFD_SEMAPHORE) ? 1 : efd->count;
    memcpy(buf, &value, sizeof(uint64_t));

    efd->count -= value;
    return sizeof(uint64_t);
}

static ssize_t eventfd_write(eventfd_t *efd, const void *buf, size_t offset,
                             size_t len) {
    uint64_t value;
    memcpy(&value, buf, sizeof(uint64_t));

    if (UINT64_MAX - efd->count < value)
        return -EINVAL;

    efd->count += value;

    return sizeof(uint64_t);
}

bool eventfd_close(void *current) {
    eventfd_t *efd = current;
    free(efd);

    return true;
}

static int eventfd_poll(void *file, size_t events) {
    eventfd_t *eventFd = file;
    int revents = 0;

    if (events & EPOLLIN && eventFd->count > 0)
        revents |= EPOLLIN;

    if (events & EPOLLOUT && eventFd->count < UINT64_MAX)
        revents |= EPOLLOUT;

    return revents;
}

static struct vfs_callback eventfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .remount = (vfs_remount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)eventfd_close,
    .read = (vfs_read_t)eventfd_read,
    .write = (vfs_write_t)eventfd_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = eventfd_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t eventfdfs = {
    .name = "eventfdfs",
    .magic = 0,
    .callback = &eventfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void eventfd_init() { eventfdfs_id = vfs_regist(&eventfdfs); }
