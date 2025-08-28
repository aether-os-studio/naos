#include <fs/fs_syscall.h>

uint32_t epoll_to_poll_comp(uint32_t epoll_events)
{
    uint32_t poll_events = 0;

    if (epoll_events & EPOLLIN)
        poll_events |= POLLIN;
    if (epoll_events & EPOLLOUT)
        poll_events |= POLLOUT;
    if (epoll_events & EPOLLPRI)
        poll_events |= POLLPRI;
    if (epoll_events & EPOLLERR)
        poll_events |= POLLERR;
    if (epoll_events & EPOLLHUP)
        poll_events |= POLLHUP;

    return poll_events;
}

uint32_t poll_to_epoll_comp(uint32_t poll_events)
{
    uint32_t epoll_events = 0;

    if (poll_events & POLLIN)
        epoll_events |= EPOLLIN;
    if (poll_events & POLLOUT)
        epoll_events |= EPOLLOUT;
    if (poll_events & POLLPRI)
        epoll_events |= EPOLLPRI;
    if (poll_events & POLLERR)
        epoll_events |= EPOLLERR;
    if (poll_events & POLLHUP)
        epoll_events |= EPOLLHUP;

    return epoll_events;
}

size_t sys_poll(struct pollfd *fds, int nfds, uint64_t timeout)
{
    int ready = 0;
    uint64_t start_time = nanoTime();

    bool sigexit = false;

    do
    {
        // 检查每个文件描述符
        for (int i = 0; i < nfds; i++)
        {
            fds[i].revents = 0;

            if (fds[i].fd < 0 || fds[i].fd > MAX_FD_NUM || !current_task->fd_info->fds[fds[i].fd])
            {
                return (size_t)-EBADF;
            }
            vfs_node_t node = current_task->fd_info->fds[fds[i].fd]->node;
            if (!node)
                continue;
            if (!fs_callbacks[node->fsid]->poll)
            {
                if (fds[i].events & POLLIN || fds[i].events & POLLOUT)
                {
                    fds[i].revents = fds[i].events & POLLIN ? POLLIN : POLLOUT;
                    ready++;
                }
                continue;
            }

            arch_disable_interrupt();

            int revents = epoll_to_poll_comp(vfs_poll(node, poll_to_epoll_comp(fds[i].events)));
            if (revents > 0)
            {
                fds[i].revents = revents;
                ready++;
            }
        }

        sigexit = signals_pending_quick(current_task);

        if (ready > 0 || sigexit)
            break;

        arch_yield();
    } while (timeout != 0 && ((int)timeout == -1 || (nanoTime() - start_time) < timeout));

    if (!ready && sigexit)
        return (size_t)-EINTR;

    return ready;
}

uint64_t sys_ppoll(struct pollfd *fds, uint64_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask, size_t sigsetsize)
{
    if (!fds || check_user_overflow((uint64_t)fds, nfds * sizeof(struct pollfd)))
    {
        return (uint64_t)-EFAULT;
    }
    if (sigmask && sigsetsize < sizeof(sigset_t))
    {
        return (uint64_t)-EINVAL;
    }

    sigset_t origmask;
    if (sigmask)
    {
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);
    }

    int timeout = -1;
    if (timeout_ts)
    {
        timeout = timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000;
    }

    uint64_t ret = sys_poll(fds, nfds, timeout);

    if (sigmask)
    {
        sys_ssetmask(SIG_SETMASK, &origmask, NULL);
    }

    return ret;
}

static inline struct pollfd *select_add(struct pollfd **comp, size_t *compIndex,
                                        size_t *complength, int fd, int events)
{
    if ((*compIndex + 1) * sizeof(struct pollfd) >= *complength)
    {
        *complength *= 2;
        *comp = realloc(*comp, *complength);
    }

    (*comp)[*compIndex].fd = fd;
    (*comp)[*compIndex].events = events;
    (*comp)[*compIndex].revents = 0;

    return &(*comp)[(*compIndex)++];
}

// i hate this obsolete system call and do not plan on making it efficient
static inline bool select_bitmap(uint8_t *map, int index)
{
    int div = index / 8;
    int mod = index % 8;
    return map[div] & (1 << mod);
}

static inline void select_bitmap_set(uint8_t *map, int index)
{
    int div = index / 8;
    int mod = index % 8;
    map[div] |= 1 << mod;
}

size_t sys_select(int nfds, uint8_t *read, uint8_t *write, uint8_t *except,
                  struct timeval *timeout)
{
    if (read && check_user_overflow((uint64_t)read, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    if (write && check_user_overflow((uint64_t)write, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    if (except && check_user_overflow((uint64_t)except, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    size_t complength = sizeof(struct pollfd);
    struct pollfd *comp = (struct pollfd *)malloc(complength);
    size_t compIndex = 0;
    if (read)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(read, i))
                select_add(&comp, &compIndex, &complength, i, POLLIN);
        }
    }
    if (write)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(write, i))
                select_add(&comp, &compIndex, &complength, i, POLLOUT);
        }
    }
    if (except)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(except, i))
                select_add(&comp, &compIndex, &complength, i, POLLPRI | POLLERR);
        }
    }

    int toZero = (nfds + 7) / 8;
    if (read)
        memset(read, 0, toZero);
    if (write)
        memset(write, 0, toZero);
    if (except)
        memset(except, 0, toZero);

    size_t res = sys_poll(comp, compIndex, timeout ? (timeout->tv_sec * 1000 + (timeout->tv_usec + 1000) / 1000) : -1);

    if ((int64_t)res < 0)
    {
        free(comp);
        return res;
    }

    size_t verify = 0;
    for (size_t i = 0; i < compIndex; i++)
    {
        if (!comp[i].revents)
            continue;
        if (comp[i].events & POLLIN && comp[i].revents & POLLIN)
        {
            select_bitmap_set(read, comp[i].fd);
            verify++;
        }
        if (comp[i].events & POLLOUT && comp[i].revents & POLLOUT)
        {
            select_bitmap_set(write, comp[i].fd);
            verify++;
        }
        if ((comp[i].events & POLLPRI && comp[i].revents & POLLPRI) ||
            (comp[i].events & POLLERR && comp[i].revents & POLLERR))
        {
            select_bitmap_set(except, comp[i].fd);
            verify++;
        }
    }

    free(comp);
    return verify;
}

uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timespec *timeout, WeirdPselect6 *weirdPselect6)
{
    if (readfds && check_user_overflow((uint64_t)readfds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    if (writefds && check_user_overflow((uint64_t)writefds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    if (exceptfds && check_user_overflow((uint64_t)exceptfds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    size_t sigsetsize = weirdPselect6->ss_len;
    sigset_t *sigmask = weirdPselect6->ss;

    if (sigsetsize < sizeof(sigset_t))
    {
        printk("weird sigset size\n");
        return (uint64_t)-EINVAL;
    }

    sigset_t origmask;
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);

    struct timeval timeoutConv;
    if (timeout)
    {
        timeoutConv = (struct timeval){.tv_sec = timeout->tv_sec,
                                       .tv_usec = (timeout->tv_nsec + 1000) / 1000};
    }
    else
    {
        timeoutConv = (struct timeval){.tv_sec = (uint64_t)-1,
                                       .tv_usec = (uint64_t)-1};
    }

    size_t ret = sys_select(nfds, (uint8_t *)readfds, (uint8_t *)writefds,
                            (uint8_t *)exceptfds, &timeoutConv);

    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, NULL);

    return ret;
}
