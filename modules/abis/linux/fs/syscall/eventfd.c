#include <fs/fs_syscall.h>
#include <fs/proc.h>
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
    efd->flags = flags & EFD_SEMAPHORE;

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

        fd_t *new_fd = fd_create(node, O_RDWR | (flags & EFD_NONBLOCK),
                                 !!(flags & EFD_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

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

    while (true) {
        uint64_t old_count = __atomic_load_n(&efd->count, __ATOMIC_ACQUIRE);
        if (old_count != 0) {
            value = (efd->flags & EFD_SEMAPHORE) ? 1 : old_count;
            uint64_t new_count = old_count - value;
            uint64_t expected = old_count;
            if (__atomic_compare_exchange_n(&efd->count, &expected, new_count,
                                            false, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
                memcpy(buf, &value, sizeof(uint64_t));
                vfs_poll_notify(efd->node,
                                EPOLLOUT | (new_count ? EPOLLIN : 0));
                return sizeof(uint64_t);
            }
            continue;
        }

        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EAGAIN;

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
        vfs_poll_wait_arm(fd->node, &wait);
        int reason = vfs_poll_wait_sleep(fd->node, &wait, -1, "eventfd_read");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK)
            return -EINTR;
    }
}

static ssize_t eventfd_write(fd_t *fd, const void *buf, size_t offset,
                             size_t len) {
    eventfd_t *efd = fd->node->handle;

    uint64_t value;
    memcpy(&value, buf, sizeof(uint64_t));

    while (true) {
        uint64_t old_count = __atomic_load_n(&efd->count, __ATOMIC_ACQUIRE);
        if (UINT64_MAX - old_count < value)
            return -EINVAL;

        uint64_t new_count = old_count + value;
        uint64_t expected = old_count;
        if (__atomic_compare_exchange_n(&efd->count, &expected, new_count,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            break;
        }
    }
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
    uint64_t count = __atomic_load_n(&eventFd->count, __ATOMIC_ACQUIRE);

    if (events & EPOLLIN && count > 0)
        revents |= EPOLLIN;

    if (events & EPOLLOUT && count < UINT64_MAX)
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
