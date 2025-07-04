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
        if (!current_task->fds[i])
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

    current_task->fds[fd] = malloc(sizeof(fd_t));
    current_task->fds[fd]->node = node;
    current_task->fds[fd]->offset = 0;
    current_task->fds[fd]->flags = 0;

    return fd;
}

int sys_timerfd_settime(int fd, int flags, const struct itimerval *new_value, struct itimerval *old_value)
{
    if (fd >= MAX_FD_NUM || !current_task->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fds[fd]->node;
    timerfd_t *tfd = node->handle;

    if (old_value)
    {
        uint64_t remaining = tfd->timer.expires > jiffies ? tfd->timer.expires - jiffies : 0;

        old_value->it_interval.tv_sec = tfd->timer.interval / 1000;
        old_value->it_interval.tv_usec = (tfd->timer.interval % 1000) * 1000;

        old_value->it_value.tv_sec = remaining / 1000;
        old_value->it_value.tv_usec = (remaining % 1000) * 1000;
    }

    uint64_t interval = new_value->it_interval.tv_sec * 1000 +
                        new_value->it_interval.tv_usec / 1000000;
    uint64_t expires = new_value->it_value.tv_sec * 1000 +
                       new_value->it_value.tv_usec / 1000000;

    tfd->timer.interval = interval;
    tfd->timer.expires = jiffies + expires;

    return 0;
}

bool sys_timerfd_close(void *current)
{
    free(current);
    return true;
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
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)dummy,
};

void timerfd_init()
{
    timerfdfs_id = vfs_regist("timerfd", &timerfd_callbacks);
    timerfdfs_root = vfs_node_alloc(rootdir, "timer");
    timerfdfs_root->type = file_dir;
    timerfdfs_root->mode = 0644;
    timerfdfs_root->fsid = timerfdfs_id;
}
