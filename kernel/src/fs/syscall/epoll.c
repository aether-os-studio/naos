#include <fs/fs_syscall.h>

vfs_node_t epollfs_root;
int epollfs_id;
int epollfd_id = 0;

static int dummy()
{
    return 0;
}

// epoll API
size_t epoll_create1(int flags)
{
    int i = -1;
    for (i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return -EBADF;
    }

    char buf[256];
    sprintf(buf, "epoll%d", epollfd_id++);
    vfs_node_t node = vfs_node_alloc(epollfs_root, buf);
    node->type = file_epoll;
    node->refcount++;
    epoll_t *epoll = malloc(sizeof(epoll_t));
    epoll->lock = false;
    epoll->firstEpollWatch = NULL;
    epoll->reference_count = 1;
    node->mode = 0700;
    node->handle = epoll;
    node->fsid = epollfs_id;

    current_task->fds[i] = malloc(sizeof(fd_t));
    current_task->fds[i]->node = node;
    current_task->fds[i]->offset = 0;
    current_task->fds[i]->flags = 0;

    return i;
}

uint64_t sys_epoll_create(int size)
{
    return epoll_create1(0);
}

uint64_t epoll_wait(vfs_node_t epollFd, struct epoll_event *events, int maxevents, int timeout)
{
    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    epoll_t *epoll = epollFd->handle;

    bool sigexit = false;

    int ready = 0;
    size_t target = nanoTime() + timeout;
    do
    {
        while (epoll->lock)
        {
            arch_pause();
        }

        epoll->lock = true;
        epoll_watch_t *browse = epoll->firstEpollWatch;

        while (browse && ready < maxevents)
        {
            int revents = vfs_poll(browse->fd, browse->watchEvents);
            if (revents != 0 && ready < maxevents)
            {
                events[ready].events = revents;
                events[ready].data = (epoll_data_t)browse->userlandData;
                ready++;
            }
            browse = browse->next;
        }

        epoll->lock = false;

        sigexit = signals_pending_quick(current_task);

        if (ready > 0 || sigexit)
            break;

#if defined(__x86_64__)
        arch_enable_interrupt();
#endif

        arch_pause();
    } while (timeout != 0 && (timeout == -1 || nanoTime() < target));

#if defined(__x86_64__)
    arch_disable_interrupt();
#endif

    if (!ready && sigexit)
        return (uint64_t)-EINTR;

    return ready;
}

size_t epoll_ctl(vfs_node_t epollFd, int op, int fd, struct epoll_event *event)
{
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_DEL && op != EPOLL_CTL_MOD)
        return (uint64_t)(-EINVAL);
    if (op & EPOLLET || op & EPOLLONESHOT || op & EPOLLEXCLUSIVE)
    {
        printk("bad opcode!\n"); // could atl do oneshot, but later
        return (uint64_t)(-ENOSYS);
    }

    epoll_t *epoll = epollFd->handle;
    if (!epoll)
        return -EINVAL;

    size_t ret = 0;

    if (!current_task->fds[fd])
    {
        ret = (uint64_t)(-EBADF);
        goto cleanup;
    }

    vfs_node_t fdNode = current_task->fds[fd]->node;

    switch (op)
    {
    case EPOLL_CTL_ADD:
    {
        epoll_watch_t *epollWatch = malloc(sizeof(epoll_watch_t));
        epollWatch->fd = fdNode;
        epollWatch->watchEvents = event->events;
        epollWatch->userlandData = (uint64_t)event->data.ptr;
        epollWatch->next = NULL;
        epoll_watch_t *current = epoll->firstEpollWatch;
        if (current)
        {
            while (current->next)
                current = current->next;
            current->next = epollWatch;
        }
        else
        {
            epoll->firstEpollWatch = epollWatch;
        }
        break;
    }
    case EPOLL_CTL_MOD:
    {
        epoll_watch_t *browse = epoll->firstEpollWatch;
        while (browse)
        {
            if (browse->fd == fdNode)
                break;
            browse = browse->next;
        }
        if (!browse)
        {
            ret = (uint64_t)(-ENOENT);
            goto cleanup;
        }
        browse->watchEvents = event->events;
        browse->userlandData = (uint64_t)event->data.ptr;
        break;
    }
    case EPOLL_CTL_DEL:
    {
        epoll_watch_t *browse = epoll->firstEpollWatch;
        epoll_watch_t *prev = NULL;
        while (browse)
        {
            if (browse->fd == fdNode)
                break;
            prev = browse;
            browse = browse->next;
        }
        if (!browse)
        {
            ret = (uint64_t)(-ENOENT);
            goto cleanup;
        }
        prev->next = browse->next;
        free(browse);
        break;
    }
    default:
        printk("[epoll] Unhandled opcode %d\n", op);
        break;
    }

cleanup:
    return ret;
}

size_t epoll_pwait(vfs_node_t epollFd, struct epoll_event *events, int maxevents,
                   int timeout, sigset_t *sigmask, size_t sigsetsize)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    if (sigsetsize < sizeof(sigset_t))
    {
        printk("weird sigset size\n");
        return (uint64_t)(-EINVAL);
    }

    sigset_t origmask;
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);
    size_t epollRet = epoll_wait(epollFd, events, maxevents, timeout);
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, 0);

    return epollRet;
}

uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_wait(node, events, maxevents, timeout);
}

uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (check_user_overflow((uint64_t)event, sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_ctl(node, op, fd, event);
}

uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout, sigset_t *sigmask,
                         size_t sigsetsize)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_pwait(node, events, maxevents, timeout, sigmask, sigsetsize);
}

uint64_t sys_epoll_create1(int flags) { return epoll_create1(flags); }

bool epollfs_close(void *current)
{
    epoll_t *epoll = current;
    epoll->reference_count--;
    // if (!epoll->reference_count)
    //     return true;
    return false;
}

static int epoll_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

static struct vfs_callback epoll_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = epollfs_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = epoll_poll,
};

void epoll_init()
{
    epollfs_id = vfs_regist("epollfs", &epoll_callbacks);
    epollfs_root = vfs_node_alloc(rootdir, "epoll");
    epollfs_root->type = file_dir;
    epollfs_root->mode = 0644;
    epollfs_root->fsid = epollfs_id;
}
