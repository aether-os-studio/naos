#include <fs/fs_syscall.h>
#include <task/task.h>
#include <task/signal.h>

uint32_t epoll_to_poll_comp(uint32_t epoll_events) {
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
    if (epoll_events & EPOLLNVAL)
        poll_events |= POLLNVAL;
    if (epoll_events & EPOLLRDHUP)
        poll_events |= POLLRDHUP;

    return poll_events;
}

uint32_t poll_to_epoll_comp(uint32_t poll_events) {
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
    if (poll_events & POLLNVAL)
        epoll_events |= EPOLLNVAL;
    if (poll_events & POLLRDHUP)
        epoll_events |= EPOLLRDHUP;

    return epoll_events;
}

static int poll_scan_ready(struct pollfd *fds, int nfds) {
    int ready = 0;

    for (int i = 0; i < nfds; i++) {
        struct vfs_file *file;

        fds[i].revents = 0;
        if (fds[i].fd < 0)
            continue;

        file = task_get_file(current_task, fds[i].fd);
        if (!file) {
            fds[i].revents |= POLLNVAL;
            ready++;
            continue;
        }

        uint32_t query_events = poll_to_epoll_comp(fds[i].events) | EPOLLERR |
                                EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
        int polled = EPOLLNVAL;
        if (file->f_op && file->f_op->poll)
            polled = (int)file->f_op->poll(file, NULL) & (int)query_events;
        if (polled < 0)
            polled = 0;

        int revents = epoll_to_poll_comp((uint32_t)polled);
        if (revents > 0) {
            fds[i].revents = revents;
            ready++;
        }
        vfs_file_put(file);
    }

    return ready;
}

static void poll_arm_waiters(struct pollfd *fds, int nfds,
                             vfs_poll_wait_t *waits) {
    for (int i = 0; i < nfds; i++) {
        struct vfs_file *file;
        vfs_node_t *node;

        if (fds[i].fd < 0)
            continue;

        file = task_get_file(current_task, fds[i].fd);
        if (!file)
            continue;

        node = file->node;
        uint32_t query_events = poll_to_epoll_comp(fds[i].events) | EPOLLERR |
                                EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
        vfs_poll_wait_init(&waits[i], current_task, query_events);
        vfs_poll_wait_arm(node, &waits[i]);
        vfs_file_put(file);
    }
}

static void poll_disarm_waiters(vfs_poll_wait_t *waits, int nfds) {
    for (int i = 0; i < nfds; i++) {
        if (waits[i].armed) {
            vfs_poll_wait_disarm(&waits[i]);
        }
    }
}

static size_t do_poll(struct pollfd *fds, int nfds, uint64_t timeout) {
    if (nfds < 0)
        return (size_t)-EINVAL;
    if (nfds > 0 && !fds)
        return (size_t)-EFAULT;
    if (!current_task)
        return (size_t)-EINVAL;

    vfs_poll_wait_t *waits = NULL;
    if (nfds > 0) {
        waits = calloc(nfds, sizeof(vfs_poll_wait_t));
        if (!waits)
            return (size_t)-ENOMEM;
    }

    int ready = 0;
    bool irq_state = arch_interrupt_enabled();
    uint64_t start_time = nano_time();
    bool infinite_timeout = ((int64_t)timeout < 0);
    uint64_t timeout_ns = 0;
    if (!infinite_timeout) {
        timeout_ns = timeout * 1000000ULL;
    }

    do {
        arch_enable_interrupt();

        ready = poll_scan_ready(fds, nfds);

        if (ready > 0)
            break;

        if (task_signal_has_deliverable(current_task)) {
            ready = -EINTR;
            break;
        }

        if (!infinite_timeout && timeout == 0)
            break;

        poll_arm_waiters(fds, nfds, waits);
        ready = poll_scan_ready(fds, nfds);
        if (ready > 0) {
            poll_disarm_waiters(waits, nfds);
            break;
        }

        if (task_signal_has_deliverable(current_task)) {
            poll_disarm_waiters(waits, nfds);
            ready = -EINTR;
            break;
        }

        int64_t wait_ns = -1;
        if (!infinite_timeout) {
            uint64_t elapsed = nano_time() - start_time;
            if (elapsed >= timeout_ns) {
                poll_disarm_waiters(waits, nfds);
                break;
            }
            wait_ns = (int64_t)(timeout_ns - elapsed);
        }

        int64_t block_ns = wait_ns;
        if (block_ns < 0 || block_ns > 10000000LL) {
            block_ns = 10000000LL;
        }

        int block_reason =
            task_block(current_task, TASK_BLOCKING, block_ns, "poll_wait");
        poll_disarm_waiters(waits, nfds);
        if (block_reason == ETIMEDOUT) {
            continue;
        }
        if (block_reason != EOK) {
            ready = -EINTR;
            break;
        }
    } while (infinite_timeout || (nano_time() - start_time) < timeout_ns);

    free(waits);

    if (irq_state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }

    return ready;
}

size_t sys_poll(struct pollfd *fds, int nfds, uint64_t timeout) {
    size_t fds_bytes = 0;

    if (nfds < 0)
        return (size_t)-EINVAL;
    if (nfds > 0 &&
        (!fds || check_user_array_overflow((uint64_t)fds, (size_t)nfds,
                                           sizeof(*fds), &fds_bytes))) {
        return (size_t)-EFAULT;
    }

    struct pollfd *kfds = NULL;
    if (nfds > 0) {
        kfds = malloc(fds_bytes);
        if (!kfds)
            return (size_t)-ENOMEM;
        if (copy_from_user(kfds, fds, fds_bytes)) {
            free(kfds);
            return (size_t)-EFAULT;
        }
    }

    size_t ret = do_poll(kfds, nfds, timeout);

    if (kfds) {
        if ((int64_t)ret >= 0 && copy_to_user(fds, kfds, fds_bytes)) {
            free(kfds);
            return (size_t)-EFAULT;
        }
        free(kfds);
    }

    return ret;
}

uint64_t sys_ppoll(struct pollfd *fds, uint64_t nfds,
                   const struct timespec *timeout_ts, const sigset_t *sigmask,
                   size_t sigsetsize) {
    size_t fds_bytes = 0;

    if (nfds > INT32_MAX)
        return (uint64_t)-EINVAL;
    if (nfds > 0 && (!fds || check_user_array_overflow(
                                 (uint64_t)fds, (size_t)nfds,
                                 sizeof(struct pollfd), &fds_bytes))) {
        return (uint64_t)-EFAULT;
    }
    if (sigmask && sigsetsize < sizeof(sigset_t)) {
        return (uint64_t)-EINVAL;
    }

    struct pollfd *kfds = NULL;
    if (nfds > 0) {
        kfds = malloc(fds_bytes);
        if (!kfds)
            return (uint64_t)-ENOMEM;
        if (copy_from_user(kfds, fds, fds_bytes)) {
            free(kfds);
            return (uint64_t)-EFAULT;
        }
    }

    int timeout = -1;
    if (timeout_ts) {
        struct timespec ts;
        if (copy_from_user(&ts, timeout_ts, sizeof(ts))) {
            free(kfds);
            return (uint64_t)-EFAULT;
        }
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL) {
            free(kfds);
            return (uint64_t)-EINVAL;
        }
        timeout = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }

    sigset_t origmask;
    sigset_t newmask;
    if (sigmask) {
        if (copy_from_user(&newmask, sigmask, sizeof(newmask))) {
            free(kfds);
            return (uint64_t)-EFAULT;
        }
        sys_ssetmask(SIG_SETMASK, &newmask, &origmask, sizeof(sigset_t));
    }

    uint64_t ret = do_poll(kfds, (int)nfds, timeout);

    if (sigmask) {
        sys_ssetmask(SIG_SETMASK, &origmask, NULL, sizeof(sigset_t));
    }

    if (kfds) {
        if ((int64_t)ret >= 0 && copy_to_user(fds, kfds, fds_bytes)) {
            free(kfds);
            return (uint64_t)-EFAULT;
        }
        free(kfds);
    }

    return ret;
}

static inline struct pollfd *select_add(struct pollfd **comp, size_t *compIndex,
                                        size_t *complength, int fd,
                                        int events) {
    if ((*compIndex + 1) * sizeof(struct pollfd) > *complength) {
        struct pollfd *new_comp;

        *complength *= 2;
        new_comp = realloc(*comp, *complength);
        if (!new_comp)
            return NULL;
        *comp = new_comp;
    }

    (*comp)[*compIndex].fd = fd;
    (*comp)[*compIndex].events = events;
    (*comp)[*compIndex].revents = 0;

    return &(*comp)[(*compIndex)++];
}

// i hate this obsolete system call and do not plan on making it efficient
static inline bool select_bitmap(uint8_t *map, int index) {
    int div = index / 8;
    int mod = index % 8;
    return map[div] & (1 << mod);
}

static inline void select_bitmap_set(uint8_t *map, int index) {
    int div = index / 8;
    int mod = index % 8;
    map[div] |= 1 << mod;
}

size_t sys_select(int nfds, uint8_t *read, uint8_t *write, uint8_t *except,
                  struct timeval *timeout) {
    if (nfds < 0 || nfds >= MAX_FD_NUM)
        return (size_t)-EINVAL;

    size_t bitmap_bytes = ((size_t)nfds + 7) / 8;
    if ((read && check_user_overflow((uint64_t)read, bitmap_bytes)) ||
        (write && check_user_overflow((uint64_t)write, bitmap_bytes)) ||
        (except && check_user_overflow((uint64_t)except, bitmap_bytes))) {
        return (size_t)-EFAULT;
    }

    uint8_t *kread = NULL;
    uint8_t *kwrite = NULL;
    uint8_t *kexcept = NULL;
    if (bitmap_bytes) {
        if (read) {
            kread = calloc(1, bitmap_bytes);
            if (!kread)
                return (size_t)-ENOMEM;
            if (copy_from_user(kread, read, bitmap_bytes))
                goto fault;
        }
        if (write) {
            kwrite = calloc(1, bitmap_bytes);
            if (!kwrite)
                goto nomem;
            if (copy_from_user(kwrite, write, bitmap_bytes))
                goto fault;
        }
        if (except) {
            kexcept = calloc(1, bitmap_bytes);
            if (!kexcept)
                goto nomem;
            if (copy_from_user(kexcept, except, bitmap_bytes))
                goto fault;
        }
    }

    size_t complength = sizeof(struct pollfd) * MAX((size_t)nfds * 3, 1);
    struct pollfd *comp = (struct pollfd *)malloc(complength);
    if (!comp)
        goto nomem;
    size_t compIndex = 0;
    if (kread) {
        for (int i = 0; i < nfds; i++) {
            if (select_bitmap(kread, i))
                select_add(&comp, &compIndex, &complength, i, POLLIN);
        }
    }
    if (kwrite) {
        for (int i = 0; i < nfds; i++) {
            if (select_bitmap(kwrite, i))
                select_add(&comp, &compIndex, &complength, i, POLLOUT);
        }
    }
    if (kexcept) {
        for (int i = 0; i < nfds; i++) {
            if (select_bitmap(kexcept, i))
                select_add(&comp, &compIndex, &complength, i,
                           POLLPRI | POLLERR);
        }
    }

    if (kread)
        memset(kread, 0, bitmap_bytes);
    if (kwrite)
        memset(kwrite, 0, bitmap_bytes);
    if (kexcept)
        memset(kexcept, 0, bitmap_bytes);

    size_t res = do_poll(
        comp, compIndex,
        timeout ? (timeout->tv_sec * 1000 + (timeout->tv_usec + 1000) / 1000)
                : -1);

    if ((int64_t)res < 0) {
        free(comp);
        free(kread);
        free(kwrite);
        free(kexcept);
        return res;
    }

    size_t verify = 0;
    for (size_t i = 0; i < compIndex; i++) {
        if (!comp[i].revents)
            continue;
        if (kread && comp[i].events & POLLIN && comp[i].revents & POLLIN) {
            select_bitmap_set(kread, comp[i].fd);
            verify++;
        }
        if (kwrite && comp[i].events & POLLOUT && comp[i].revents & POLLOUT) {
            select_bitmap_set(kwrite, comp[i].fd);
            verify++;
        }
        if (kexcept &&
            ((comp[i].events & POLLPRI && comp[i].revents & POLLPRI) ||
             (comp[i].events & POLLERR && comp[i].revents & POLLERR))) {
            select_bitmap_set(kexcept, comp[i].fd);
            verify++;
        }
    }

    if ((kread && copy_to_user(read, kread, bitmap_bytes)) ||
        (kwrite && copy_to_user(write, kwrite, bitmap_bytes)) ||
        (kexcept && copy_to_user(except, kexcept, bitmap_bytes))) {
        free(comp);
        free(kread);
        free(kwrite);
        free(kexcept);
        return (size_t)-EFAULT;
    }

    free(comp);
    free(kread);
    free(kwrite);
    free(kexcept);
    return verify;

fault:
    free(kread);
    free(kwrite);
    free(kexcept);
    return (size_t)-EFAULT;

nomem:
    free(kread);
    free(kwrite);
    free(kexcept);
    return (size_t)-ENOMEM;
}

uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *exceptfds, struct timespec *timeout,
                      weird_pselect6_t *weird_pselect6) {
    if (nfds >= MAX_FD_NUM)
        return (size_t)-EINVAL;

    size_t bitmap_bytes = (nfds + 7) / 8;
    if (readfds && check_user_overflow((uint64_t)readfds, bitmap_bytes)) {
        return (size_t)-EFAULT;
    }
    if (writefds && check_user_overflow((uint64_t)writefds, bitmap_bytes)) {
        return (size_t)-EFAULT;
    }
    if (exceptfds && check_user_overflow((uint64_t)exceptfds, bitmap_bytes)) {
        return (size_t)-EFAULT;
    }

    size_t sigsetsize = 0;
    sigset_t newmask = 0;
    sigset_t *sigmask = NULL;
    sigset_t origmask = 0;
    if (weird_pselect6) {
        weird_pselect6_t args;
        if (copy_from_user(&args, weird_pselect6, sizeof(args)))
            return (size_t)-EFAULT;
        sigsetsize = args.ss_len;
        if (args.ss) {
            if (copy_from_user(&newmask, args.ss, sizeof(newmask)))
                return (size_t)-EFAULT;
            sigmask = &newmask;
        }

        if (sigmask)
            sys_ssetmask(SIG_SETMASK, sigmask, &origmask, sigsetsize);
    }

    struct timeval timeoutConv;
    if (timeout) {
        struct timespec ts;
        if (copy_from_user(&ts, timeout, sizeof(ts)))
            return (size_t)-EFAULT;
        timeoutConv = (struct timeval){.tv_sec = ts.tv_sec,
                                       .tv_usec = (ts.tv_nsec + 1000) / 1000};
    } else {
        timeoutConv =
            (struct timeval){.tv_sec = (uint64_t)-1, .tv_usec = (uint64_t)-1};
    }

    size_t ret = sys_select(nfds, (uint8_t *)readfds, (uint8_t *)writefds,
                            (uint8_t *)exceptfds, &timeoutConv);

    if (weird_pselect6) {
        if (sigmask)
            sys_ssetmask(SIG_SETMASK, &origmask, NULL, sigsetsize);
    }

    return ret;
}
