#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>

int epollfs_id;

#define EPOLL_ALWAYS_EVENTS (EPOLLERR | EPOLLHUP | EPOLLNVAL)
#define EPOLL_CONTROL_FLAGS                                                    \
    (EPOLLET | EPOLLONESHOT | EPOLLWAKEUP | EPOLLEXCLUSIVE)
#define EPOLL_IN_EVENTS (EPOLLIN | EPOLLRDNORM | EPOLLRDBAND | EPOLLRDHUP)
#define EPOLL_OUT_EVENTS (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)
#define EPOLL_PRI_EVENTS (EPOLLPRI | EPOLLMSG)

static uint32_t epoll_filter_events(uint32_t events) {
    return events & ~EPOLL_CONTROL_FLAGS;
}

static void epoll_watch_sync_seq(epoll_watch_t *watch) {
    if (!watch || !watch->file)
        return;
    watch->last_seq_in = watch->file->poll_seq_in;
    watch->last_seq_out = watch->file->poll_seq_out;
    watch->last_seq_pri = watch->file->poll_seq_pri;
}

static bool epoll_watch_has_seq_update(epoll_watch_t *watch,
                                       uint32_t ready_events) {
    if (!watch || !watch->file)
        return false;

    if ((ready_events & EPOLL_IN_EVENTS) &&
        watch->file->poll_seq_in != watch->last_seq_in) {
        return true;
    }
    if ((ready_events & EPOLL_OUT_EVENTS) &&
        watch->file->poll_seq_out != watch->last_seq_out) {
        return true;
    }
    if ((ready_events & EPOLL_PRI_EVENTS) &&
        watch->file->poll_seq_pri != watch->last_seq_pri) {
        return true;
    }
    return false;
}

static int epoll_collect_ready_locked(epoll_t *epoll,
                                      struct epoll_event *events,
                                      int maxevents) {
    int ready = 0;

    epoll_watch_t *browse, *tmp;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (browse->disabled)
            continue;
        if (ready >= maxevents)
            break;
        if (!browse->file || !browse->file->handle)
            continue;

        uint32_t request_events = browse->events | EPOLL_ALWAYS_EVENTS;
        int current_events = vfs_poll(browse->file, request_events);
        if (current_events < 0)
            current_events = 0;
        uint32_t ready_events =
            ((uint32_t)current_events & browse->events) |
            ((uint32_t)current_events & EPOLL_ALWAYS_EVENTS);

        if (ready_events) {
            bool emit = true;
            if (browse->edge_trigger) {
                uint32_t state_events = ready_events & ~EPOLL_ALWAYS_EVENTS;
                uint32_t raised = state_events & ~browse->last_events;
                bool seq_update =
                    epoll_watch_has_seq_update(browse, state_events);
                emit = !!(raised || seq_update ||
                          (ready_events & EPOLL_ALWAYS_EVENTS));
                browse->last_events = state_events;
                if (emit || !state_events) {
                    epoll_watch_sync_seq(browse);
                }
            } else {
                browse->last_events = ready_events & ~EPOLL_ALWAYS_EVENTS;
                epoll_watch_sync_seq(browse);
            }

            if (emit) {
                events[ready].events = ready_events;
                events[ready].data.u64 = browse->data;
                if (browse->one_shot)
                    browse->disabled = true;
                ready++;
            }
        } else if (browse->edge_trigger) {
            browse->last_events = 0;
            epoll_watch_sync_seq(browse);
        }
    }

    return ready;
}

static int epoll_arm_waiters_locked(epoll_t *epoll, vfs_poll_wait_t **waits_out,
                                    size_t *count_out) {
    *waits_out = NULL;
    *count_out = 0;

    size_t count = 0;
    epoll_watch_t *browse, *tmp;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (browse->disabled)
            continue;
        if (!browse->file || !browse->file->handle)
            continue;
        count++;
    }

    if (!count)
        return 0;

    vfs_poll_wait_t *waits = calloc(count, sizeof(vfs_poll_wait_t));
    if (!waits)
        return -ENOMEM;

    size_t idx = 0;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (browse->disabled)
            continue;
        if (!browse->file || !browse->file->handle)
            continue;
        uint32_t request_events = browse->events | EPOLL_ALWAYS_EVENTS;
        vfs_poll_wait_init(&waits[idx], current_task, request_events);
        vfs_poll_wait_arm(browse->file, &waits[idx]);
        idx++;
    }

    *waits_out = waits;
    *count_out = idx;
    return 0;
}

static void epoll_disarm_waiters(vfs_poll_wait_t *waits, size_t count) {
    if (!waits)
        return;
    for (size_t i = 0; i < count; i++) {
        if (waits[i].armed)
            vfs_poll_wait_disarm(&waits[i]);
    }
    free(waits);
}

// epoll API
size_t epoll_create1(int flags) {
    if (flags & ~O_CLOEXEC)
        return -EINVAL;

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->type = file_epoll;
    node->refcount++;
    epoll_t *epoll = malloc(sizeof(epoll_t));
    mutex_init(&epoll->lock);
    llist_init_head(&epoll->watches);
    node->mode = 0700;
    node->handle = epoll;
    node->fsid = epollfs_id;

    int ret = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        int i = -1;
        for (int idx = 0; idx < MAX_FD_NUM; idx++) {
            if (current_task->fd_info->fds[idx] == NULL) {
                i = idx;
                break;
            }
        }

        if (i < 0)
            break;

        fd_t *new_fd = malloc(sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }

        memset(new_fd, 0, sizeof(fd_t));
        new_fd->node = node;
        new_fd->offset = 0;
        new_fd->flags = flags & ~(uint64_t)O_CLOEXEC;
        new_fd->close_on_exec = !!(flags & O_CLOEXEC);
        current_task->fd_info->fds[i] = new_fd;
        procfs_on_open_file(current_task, i);
        ret = i;
    });

    if (ret < 0) {
        vfs_free(node);
    }

    return ret;
}

uint64_t sys_epoll_create(int size) { return epoll_create1(0); }

uint64_t epoll_wait(vfs_node_t epollFd, struct epoll_event *events,
                    int maxevents, int64_t timeout) {
    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    if (!epollFd || epollFd->fsid != epollfs_id)
        return (uint64_t)-EBADF;

    epoll_t *epoll = epollFd->handle;
    if (!epoll)
        return -EINVAL;

    int ready = 0;
    bool irq_state = arch_interrupt_enabled();
    uint64_t start = nano_time();
    bool infinite_timeout = (timeout < 0);
    uint64_t timeout_ns = timeout > 0 ? (uint64_t)timeout : 0;

    while (true) {
        arch_enable_interrupt();

        mutex_lock(&epoll->lock);
        ready = epoll_collect_ready_locked(epoll, events, maxevents);
        if (ready > 0) {
            mutex_unlock(&epoll->lock);
            break;
        }

        if (timeout == 0) {
            mutex_unlock(&epoll->lock);
            break;
        }

        vfs_poll_wait_t *waits = NULL;
        size_t waits_count = 0;
        int arm_ret = epoll_arm_waiters_locked(epoll, &waits, &waits_count);
        mutex_unlock(&epoll->lock);
        if (arm_ret < 0) {
            ready = arm_ret;
            break;
        }

        mutex_lock(&epoll->lock);
        ready = epoll_collect_ready_locked(epoll, events, maxevents);
        mutex_unlock(&epoll->lock);
        if (ready > 0) {
            epoll_disarm_waiters(waits, waits_count);
            break;
        }

        int64_t wait_ns = -1;
        if (!infinite_timeout) {
            uint64_t elapsed = nano_time() - start;
            if (elapsed >= timeout_ns) {
                epoll_disarm_waiters(waits, waits_count);
                break;
            }
            wait_ns = (int64_t)(timeout_ns - elapsed);
        }

        int block_reason =
            task_block(current_task, TASK_BLOCKING, wait_ns, "epoll_wait");
        epoll_disarm_waiters(waits, waits_count);

        if (block_reason == ETIMEDOUT) {
            break;
        }
        if (block_reason != EOK) {
            ready = -EINTR;
            break;
        }

        if (!infinite_timeout && (nano_time() - start) >= timeout_ns) {
            break;
        }
    }

    if (irq_state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }
    return ready;
}

size_t epoll_ctl(vfs_node_t epollFd, int op, int fd,
                 struct epoll_event *event) {
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_DEL && op != EPOLL_CTL_MOD)
        return (uint64_t)(-EINVAL);

    if (!epollFd || epollFd->fsid != epollfs_id)
        return (uint64_t)(-EINVAL);

    epoll_t *epoll = epollFd->handle;
    if (!epoll)
        return -EINVAL;

    // 检查文件描述符有效性
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd]) {
        return (uint64_t)(-EBADF);
    }
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) && !event) {
        return (uint64_t)(-EFAULT);
    }

    fd_t *f = current_task->fd_info->fds[fd];

    mutex_lock(&epoll->lock);

    epoll_watch_t *existing = NULL;
    epoll_watch_t *b, *t;
    llist_for_each(b, t, &epoll->watches, node) {
        if (b->file == f->node) {
            existing = b;
            break;
        }
    }

    int ret = 0;

    switch (op) {
    case EPOLL_CTL_ADD:
        if (existing) {
            ret = -EEXIST;
            break;
        }

        epoll_watch_t *new_watch = malloc(sizeof(epoll_watch_t));
        if (!new_watch) {
            ret = -ENOMEM;
            break;
        }

        new_watch->file = f->node;
        f->node->refcount++;
        new_watch->events = epoll_filter_events(event->events);
        new_watch->data = event->data.u64;
        new_watch->edge_trigger = (event->events & EPOLLET) != 0;
        new_watch->one_shot = (event->events & EPOLLONESHOT) != 0;
        new_watch->disabled = false;
        new_watch->last_events = 0;
        epoll_watch_sync_seq(new_watch);
        llist_init_head(&new_watch->node);
        llist_append(&epoll->watches, &new_watch->node);
        break;

    case EPOLL_CTL_DEL:
        if (!existing) {
            ret = -ENOENT;
            break;
        }

        if (existing->file && existing->file->refcount > 0)
            existing->file->refcount--;
        llist_delete(&existing->node);

        free(existing);
        break;

    case EPOLL_CTL_MOD:
        if (!existing) {
            ret = -ENOENT;
            break;
        }

        existing->events = epoll_filter_events(event->events);
        existing->data = event->data.u64;
        existing->edge_trigger = (event->events & EPOLLET) != 0;
        existing->one_shot = (event->events & EPOLLONESHOT) != 0;
        existing->disabled = false;
        existing->last_events = 0;
        epoll_watch_sync_seq(existing);
        break;

    default:
        ret = -EINVAL;
        break;
    }

    mutex_unlock(&epoll->lock);
    return ret;
}

size_t epoll_pwait(vfs_node_t epollFd, struct epoll_event *events,
                   int maxevents, int64_t timeout, sigset_t *sigmask,
                   size_t sigsetsize) {
    if (check_user_overflow((uint64_t)events,
                            maxevents * sizeof(struct epoll_event))) {
        return (uint64_t)-EFAULT;
    }

    sigset_t origmask;
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask, sizeof(sigset_t));
    size_t epollRet = epoll_wait(epollFd, events, maxevents, timeout);
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, 0, sizeof(sigset_t));

    return epollRet;
}

uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                        int timeout) {
    if (check_user_overflow((uint64_t)events,
                            maxevents * sizeof(struct epoll_event))) {
        return (uint64_t)-EFAULT;
    }
    if (epfd < 0 || epfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[epfd] == NULL) {
        return (uint64_t)-EBADF;
    }
    vfs_node_t node = current_task->fd_info->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    uint64_t timeout_ns;
    if (timeout < 0) {
        timeout_ns = (uint64_t)-1;
    } else {
        timeout_ns = (uint64_t)timeout * 1000000ULL;
    }
    return epoll_wait(node, events, maxevents, timeout_ns);
}

uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
        check_user_overflow((uint64_t)event, sizeof(struct epoll_event))) {
        return (uint64_t)-EFAULT;
    }
    if (epfd < 0 || epfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[epfd] == NULL) {
        return (uint64_t)-EBADF;
    }
    vfs_node_t node = current_task->fd_info->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_ctl(node, op, fd, event);
}

uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                         int timeout, sigset_t *sigmask, size_t sigsetsize) {
    if (check_user_overflow((uint64_t)events,
                            maxevents * sizeof(struct epoll_event))) {
        return (uint64_t)-EFAULT;
    }
    if (epfd < 0 || epfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[epfd] == NULL) {
        return (uint64_t)-EBADF;
    }
    vfs_node_t node = current_task->fd_info->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    int64_t timeout_ns;
    if (timeout < 0) {
        timeout_ns = -1;
    } else {
        timeout_ns = (int64_t)timeout * 1000000LL;
    }
    return epoll_pwait(node, events, maxevents, timeout_ns, sigmask,
                       sigsetsize);
}

uint64_t sys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                          struct timespec *timeout, sigset_t *sigmask,
                          size_t sigsetsize) {
    if (check_user_overflow((uint64_t)events,
                            maxevents * sizeof(struct epoll_event))) {
        return (uint64_t)-EFAULT;
    }
    if (epfd < 0 || epfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[epfd] == NULL) {
        return (uint64_t)-EBADF;
    }
    vfs_node_t node = current_task->fd_info->fds[epfd]->node;
    if (!node)
        return (uint64_t)-EBADF;
    uint64_t timeout_ns;
    if (!timeout) {
        timeout_ns = -1;
    } else {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= 1000000000LL) {
            return (uint64_t)-EINVAL;
        }
        timeout_ns = timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
    }
    return epoll_pwait(node, events, maxevents, timeout_ns, sigmask,
                       sigsetsize);
}

uint64_t sys_epoll_create1(int flags) { return epoll_create1(flags); }

bool epollfs_close(vfs_node_t node) {
    epoll_t *epoll = node ? node->handle : NULL;
    if (!epoll)
        return true;

    int browse_count = 0;
    epoll_watch_t *browse, *tmp;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (!browse->file)
            continue;
        browse->file->refcount--;
        browse_count++;
    }

    if (!browse_count)
        goto ret;

    epoll_watch_t **browses = calloc(browse_count, sizeof(epoll_watch_t *));

    browse_count = 0;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (!browse->file)
            continue;
        browses[browse_count++] = browse;
        browse->file = NULL;
    }

    for (int i = 0; i < browse_count; i++) {
        llist_delete(&browses[i]->node);
        free(browses[i]);
    }
    free(browses);

ret:
    free(epoll);

    return true;
}

static int epoll_poll(vfs_node_t node, size_t event) {
    epoll_t *epoll = node ? node->handle : NULL;
    if (!epoll)
        return EPOLLNVAL;
    int revents = 0;

    epoll_watch_t *browse, *tmp;
    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (!browse->file)
            continue;
        if (!browse->file->handle)
            continue;
        int ret = vfs_poll(browse->file, event);
        if (ret) {
            revents |= EPOLLIN;
            break;
        }
    }

    return revents;
}

static vfs_operations_t epoll_vfs_ops = {
    .close = epollfs_close,
    .poll = epoll_poll,
    .free_handle = vfs_generic_free_handle,
};

fs_t epollfs = {
    .name = "epollfs",
    .magic = 0,
    .ops = &epoll_vfs_ops,
    .flags = FS_FLAGS_HIDDEN,
};

void epoll_init() { epollfs_id = vfs_regist(&epollfs); }
