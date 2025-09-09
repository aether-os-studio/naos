#include <fs/fs_syscall.h>
#include <arch/arch.h>
#include <libs/klibc.h>
#include <task/signal.h>

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
    current_task->fd_info->fds[fd]->flags = flags;

    return fd;
}

// 统一的当前时间获取函数
static uint64_t get_current_time_ns(int clock_type)
{
    if (clock_type == CLOCK_MONOTONIC)
    {
        return nanoTime(); // 单调时钟，直接返回纳秒
    }
    else // CLOCK_REALTIME
    {
        tm time;
        time_read(&time);
        return (uint64_t)mktime(&time) * 1000000000ULL + nanoTime() % 1000000000ULL;
    }
}

extern volatile struct limine_date_at_boot_request boot_time_request;

int sys_timerfd_settime(int fd, int flags, const struct itimerval *new_value, struct itimerval *old_value)
{
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;
    timerfd_t *tfd = node->handle;

    // 保存旧值
    if (old_value)
    {
        uint64_t now = get_current_time_ns(tfd->timer.clock_type);
        uint64_t remaining = tfd->timer.expires > now ? tfd->timer.expires - now : 0;

        old_value->it_interval.tv_sec = tfd->timer.interval / 1000000000ULL;
        old_value->it_interval.tv_usec = (tfd->timer.interval % 1000000000ULL) / 1000ULL;
        old_value->it_value.tv_sec = remaining / 1000000000ULL;
        old_value->it_value.tv_usec = (remaining % 1000000000ULL) / 1000ULL;
    }

    // 设置新值
    uint64_t interval = new_value->it_interval.tv_sec * 1000000000ULL +
                        new_value->it_interval.tv_usec * 1000ULL;
    uint64_t value = new_value->it_value.tv_sec * 1000000000ULL +
                     new_value->it_value.tv_usec * 1000ULL;

    uint64_t expires;

    if (flags & TFD_TIMER_ABSTIME)
    {
        // 绝对时间：直接使用提供的值
        tfd->timer.clock_type = CLOCK_REALTIME;
        expires = value;
    }
    else
    {
        // 相对时间：当前时间 + 提供的值
        tfd->timer.clock_type = CLOCK_MONOTONIC;
        uint64_t now = value ? get_current_time_ns(tfd->timer.clock_type) : 0;
        expires = now + value;
    }

    tfd->timer.expires = expires;
    tfd->timer.interval = interval;
    // 只有在解除定时器（value为0）时才重置count
    if (value == 0)
    {
        tfd->count = 0;
    }

    return 0;
}

bool sys_timerfd_close(void *current)
{
    if (current)
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

    return revents;
}

ssize_t timerfd_read(fd_t *fd, void *addr, size_t offset, size_t size)
{
    void *file = fd->node->handle;
    timerfd_t *tfd = file;

    // 检查是否有待处理的超时事件
    if (tfd->count == 0)
    {
        uint64_t now = get_current_time_ns(tfd->timer.clock_type);

        // 检查定时器是否未启动
        if (tfd->timer.expires == 0)
        {
            // timerfd未启动，根据阻塞模式处理
            if (fd->flags & O_NONBLOCK)
            {
                return -EAGAIN; // 非阻塞模式，直接返回EAGAIN
            }
            else
            {
                // 阻塞模式，等待timerfd被设置
                while (tfd->timer.expires == 0)
                {
                    arch_yield();
                    if (signals_pending_quick(current_task))
                    {
                        return -EINTR;
                    }
                }
                // 定时器被设置后，重新获取当前时间
                now = get_current_time_ns(tfd->timer.clock_type);
            }
        }

        // 等待超时（如果是阻塞模式）
        if (tfd->timer.expires > 0 && now < tfd->timer.expires && !(fd->flags & O_NONBLOCK))
        {
            // 阻塞等待直到超时
            while (now < tfd->timer.expires)
            {
                arch_yield();
                now = get_current_time_ns(tfd->timer.clock_type);
                if (signals_pending_quick(current_task))
                {
                    return -EINTR;
                }
            }
        }
        else if (now < tfd->timer.expires && (fd->flags & O_NONBLOCK))
        {
            // 非阻塞模式且未超时
            return -EAGAIN;
        }
    }

    // 如果有待处理事件，直接使用现有的count
    uint64_t count = tfd->count;

    if (size < sizeof(uint64_t))
        return -EINVAL;

    *(uint64_t *)addr = count;
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
