#include <fs/fs_syscall.h>

int timerfdfs_id = 0;
static vfs_node_t timerfdfs_root = NULL;

static int timerfd_id = 0;

int sys_timerfd_create(int clockid, int flags)
{
    // 参数检查
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    // 分配文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fd_info->fds[i])
        {
            fd = i;
            break;
        }
    }
    if (fd == -1)
        return -EMFILE;

    timerfd_t *tfd = malloc(sizeof(timerfd_t));
    memset(tfd, 0, sizeof(timerfd_t));
    tfd->timer.clock_type = clockid;
    tfd->flags = flags;

    char buf[32];
    sprintf(buf, "timerfd%d", timerfd_id++);
    vfs_node_t node = vfs_node_alloc(timerfdfs_root, buf);
    node->refcount++;
    node->type = file_stream;
    node->fsid = timerfdfs_id;
    node->handle = tfd;

    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->offset = 0;
    current_task->fd_info->fds[fd]->flags = 0;

    return fd;
}

static uint64_t get_current_time_ms()
{
    tm time;
    time_read(&time);
    return (uint64_t)mktime(&time) * 1000ULL;
}

static uint64_t get_current_time_ns()
{
    tm time;
    time_read(&time);
    return (uint64_t)mktime(&time) * 1000000000ULL;
}

uint64_t get_current_time(uint64_t clock_type)
{
    if (clock_type == CLOCK_MONOTONIC)
    {
        return nanoTime(); // 直接返回纳秒级单调时间
    }
    else
    {
        return get_current_time_ns(); // 使用增强版实时时钟
    }
}

extern volatile struct limine_date_at_boot_request boot_time_request;

int sys_timerfd_settime(int fd, int flags, const struct itimerval *new_value, struct itimerval *old_value)
{
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;
    timerfd_t *tfd = node->handle;

    if (old_value)
    {
        uint64_t now = get_current_time(tfd->timer.clock_type);
        uint64_t remaining = tfd->timer.expires > now ? tfd->timer.expires - now : 0;

        old_value->it_interval.tv_sec = tfd->timer.interval / 1000000000ULL;
        old_value->it_interval.tv_usec = (tfd->timer.interval % 1000000000ULL) / 1000ULL;
        old_value->it_value.tv_sec = remaining / 1000000000ULL;
        old_value->it_value.tv_usec = (remaining % 1000000000ULL) / 1000ULL;
    }

    uint64_t interval = new_value->it_interval.tv_sec * 1000000000ULL +
                        new_value->it_interval.tv_usec * 1000ULL;
    uint64_t expires = new_value->it_value.tv_sec * 1000000000ULL + new_value->it_value.tv_usec * 1000ULL;
    if (!(flags & TFD_TIMER_ABSTIME))
    {
        expires = get_current_time(tfd->timer.clock_type) + expires;
    }
    else if (tfd->timer.clock_type == CLOCK_REALTIME)
    {
        expires = expires - boot_time_request.response->timestamp * 1000000000ULL;
    }
    else if (tfd->timer.clock_type == CLOCK_MONOTONIC)
    {
        // expires = new_value->it_value.tv_sec * 1000000000ULL + new_value->it_value.tv_usec * 1000ULL;
    }
    else
    {
        printk("timerfd_settime: Unsupported clockid %d\n", tfd->timer.clock_type);
        return -EINVAL;
    }

    // todo: 处理绝对/相对时间
    tfd->timer.expires = expires;
    tfd->timer.interval = interval;

    return 0;
}

bool sys_timerfd_close(void *current)
{
    free(current);
    return true;
}

int timerfd_poll(void *file, size_t events)
{
    timerfd_t *tfd = file;

    int revents = 0;

    if (events & EPOLLIN)
    {
        if (tfd->count > 0)
        {
            revents |= EPOLLIN;
        }
    }

    if (revents && !tfd->timer.interval)
    {
        tfd->count = 0;
        tfd->timer.expires = 0;
    }

    return revents;
}

ssize_t timerfd_read(fd_t *fd, void *addr, size_t offset, size_t size)
{
    void *file = fd->node->handle;
    timerfd_t *tfd = file;
    uint64_t now = get_current_time(tfd->timer.clock_type);
    uint64_t count = 0;

    if (tfd->timer.expires > 0 && now >= tfd->timer.expires)
    {
        if (tfd->timer.interval > 0)
        {
            count = (now - tfd->timer.expires) / tfd->timer.interval + 1;
            tfd->timer.expires += count * tfd->timer.interval;

            if (tfd->timer.expires < now)
            {
                uint64_t overrun = (now - tfd->timer.expires) / tfd->timer.interval;
                count += overrun;
                tfd->timer.expires += overrun * tfd->timer.interval;
            }
        }
        else
        {
            count = 1;
            tfd->timer.expires = 0;
        }
        tfd->count = count;
    }

    if (size < sizeof(uint64_t))
        return -EINVAL;

    *(uint64_t *)addr = tfd->count;
    tfd->count = 0; // 读取后重置计数

    return sizeof(uint64_t);
}

#define TFD_IOC_SET_TICKS _IOW('T', 0, uint64_t)

int timerfd_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    timerfd_t *tfd = file;
    switch (cmd)
    {
    case TFD_IOC_SET_TICKS:
        tfd->count = arg;
        return 0;

    default:
        printk("timerfd_ioctl: Unsupported cmd %#018lx\n", cmd);
        return -ENOSYS;
    }
}

static int dummy()
{
    return 0;
}

static struct vfs_callback timerfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)sys_timerfd_close,
    .read = (vfs_read_t)timerfd_read,
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
    .ioctl = (vfs_ioctl_t)timerfd_ioctl,
    .poll = (vfs_poll_t)timerfd_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

fs_t timefdfs = {
    .name = "timefdfs",
    .magic = 0,
    .callback = &timerfd_callbacks,
};

void timerfd_init()
{
    timerfdfs_id = vfs_regist(&timefdfs);
    timerfdfs_root = vfs_node_alloc(NULL, "timer");
    timerfdfs_root->type = file_dir;
    timerfdfs_root->mode = 0644;
    timerfdfs_root->fsid = timerfdfs_id;
}
