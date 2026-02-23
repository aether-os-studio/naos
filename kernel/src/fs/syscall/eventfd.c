#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>
#include <mod/dlinker.h>

int eventfdfs_id = 0;

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

EXPORT_SYMBOL(sys_eventfd2);

// 实现读写操作
static ssize_t eventfd_read(fd_t *fd, void *buf, size_t offset, size_t len) {
    eventfd_t *efd = fd->node->handle;

    uint64_t value;

    while (efd->count == 0) {
        if (efd->flags & EFD_NONBLOCK)
            return -EAGAIN;
        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
        vfs_poll_wait_arm(fd->node, &wait);
        if (efd->count == 0) {
            int reason =
                vfs_poll_wait_sleep(fd->node, &wait, -1, "eventfd_read");
            vfs_poll_wait_disarm(&wait);
            if (reason != EOK)
                return -EINTR;
        } else {
            vfs_poll_wait_disarm(&wait);
        }
    }

    value = (efd->flags & EFD_SEMAPHORE) ? 1 : efd->count;
    memcpy(buf, &value, sizeof(uint64_t));

    efd->count -= value;
    vfs_poll_notify(efd->node, EPOLLOUT | (efd->count ? EPOLLIN : 0));
    return sizeof(uint64_t);
}

static ssize_t eventfd_write(fd_t *fd, const void *buf, size_t offset,
                             size_t len) {
    eventfd_t *efd = fd->node->handle;

    uint64_t value;
    memcpy(&value, buf, sizeof(uint64_t));

    if (UINT64_MAX - efd->count < value)
        return -EINVAL;

    efd->count += value;
    vfs_poll_notify(efd->node, EPOLLIN | EPOLLOUT);

    return sizeof(uint64_t);
}

bool eventfd_close(vfs_node_t node) {
    eventfd_t *efd = node ? node->handle : NULL;
    if (!efd)
        return true;
    free(efd);

    return true;
}

static int eventfd_poll(vfs_node_t node, size_t events) {
    eventfd_t *eventFd = node ? node->handle : NULL;
    if (!eventFd)
        return EPOLLNVAL;
    int revents = 0;

    if (events & EPOLLIN && eventFd->count > 0)
        revents |= EPOLLIN;

    if (events & EPOLLOUT && eventFd->count < UINT64_MAX)
        revents |= EPOLLOUT;

    return revents;
}

static vfs_operations_t eventfd_callbacks = {
    .close = eventfd_close,
    .read = eventfd_read,
    .write = eventfd_write,
    .poll = eventfd_poll,

    .free_handle = vfs_generic_free_handle,
};

fs_t eventfdfs = {
    .name = "eventfdfs",
    .magic = 0,
    .ops = &eventfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void eventfd_init() { eventfdfs_id = vfs_regist(&eventfdfs); }
