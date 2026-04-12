#include <init/callbacks.h>
#include <fs/fs_syscall.h>
#include <task/signal.h>
#include <task/task.h>

#define EPOLL_ALWAYS_EVENTS (EPOLLERR | EPOLLHUP | EPOLLNVAL)
#define EPOLL_CONTROL_FLAGS                                                    \
    (EPOLLET | EPOLLONESHOT | EPOLLWAKEUP | EPOLLEXCLUSIVE)
#define EPOLL_IN_EVENTS (EPOLLIN | EPOLLRDNORM | EPOLLRDBAND | EPOLLRDHUP)
#define EPOLL_OUT_EVENTS (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)
#define EPOLL_PRI_EVENTS (EPOLLPRI | EPOLLMSG)
#define EPOLLFS_MAGIC 0x65706f6cULL

typedef struct epollfs_info {
    spinlock_t lock;
    ino64_t next_ino;
} epollfs_info_t;

static struct vfs_file_system_type epollfs_fs_type;
static const struct vfs_super_operations epollfs_super_ops;
static const struct vfs_file_operations epollfs_dir_file_ops;
static const struct vfs_file_operations epollfs_file_ops;
static mutex_t epollfs_mount_lock;
static struct vfs_mount *epollfs_internal_mnt;

static inline epollfs_info_t *epollfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (epollfs_info_t *)sb->s_fs_info : NULL;
}

static inline uint32_t epoll_filter_events(uint32_t events) {
    return events & ~EPOLL_CONTROL_FLAGS;
}

static epoll_t *epoll_file_handle(struct vfs_file *file) {
    if (!file || !file->f_inode || !file->f_inode->i_sb ||
        !file->f_inode->i_sb->s_type ||
        file->f_inode->i_sb->s_type != &epollfs_fs_type) {
        return NULL;
    }

    if (file->private_data)
        return (epoll_t *)file->private_data;
    return (epoll_t *)file->f_inode->i_private;
}

static __poll_t epoll_target_poll(struct vfs_file *file, uint32_t events) {
    if (!file || !file->f_op || !file->f_op->poll)
        return EPOLLNVAL;
    return file->f_op->poll(file, NULL) & events;
}

static void epoll_watch_sync_seq(epoll_watch_t *watch) {
    if (!watch || !watch->file || !watch->file->node)
        return;
    watch->last_seq_in = watch->file->node->poll_seq_in;
    watch->last_seq_out = watch->file->node->poll_seq_out;
    watch->last_seq_pri = watch->file->node->poll_seq_pri;
}

static bool epoll_watch_has_seq_update(epoll_watch_t *watch,
                                       uint32_t ready_events) {
    if (!watch || !watch->file || !watch->file->node)
        return false;

    if ((ready_events & EPOLL_IN_EVENTS) &&
        watch->file->node->poll_seq_in != watch->last_seq_in) {
        return true;
    }
    if ((ready_events & EPOLL_OUT_EVENTS) &&
        watch->file->node->poll_seq_out != watch->last_seq_out) {
        return true;
    }
    if ((ready_events & EPOLL_PRI_EVENTS) &&
        watch->file->node->poll_seq_pri != watch->last_seq_pri) {
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
        if (!browse->file)
            continue;

        uint32_t request_events = browse->events | EPOLL_ALWAYS_EVENTS;
        uint32_t ready_events =
            epoll_target_poll(browse->file, request_events) |
            (epoll_target_poll(browse->file, EPOLL_ALWAYS_EVENTS) &
             EPOLL_ALWAYS_EVENTS);

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
                if (emit || !state_events)
                    epoll_watch_sync_seq(browse);
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
    size_t count = 0;
    epoll_watch_t *browse, *tmp;

    *waits_out = NULL;
    *count_out = 0;

    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (browse->disabled || !browse->file || !browse->file->node)
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
        if (browse->disabled || !browse->file || !browse->file->node)
            continue;
        uint32_t request_events = browse->events | EPOLL_ALWAYS_EVENTS;
        vfs_poll_wait_init(&waits[idx], current_task, request_events);
        vfs_poll_wait_arm(browse->file->node, &waits[idx]);
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

static int epollfs_release(struct vfs_inode *inode, struct vfs_file *file) {
    epoll_t *epoll = epoll_file_handle(file);
    epoll_watch_t *browse, *tmp;

    (void)inode;
    if (!epoll)
        return 0;

    llist_for_each(browse, tmp, &epoll->watches, node) {
        if (browse->file)
            vfs_file_put(browse->file);
        llist_delete(&browse->node);
        free(browse);
    }

    free(epoll);
    file->private_data = NULL;
    if (file->f_inode)
        file->f_inode->i_private = NULL;
    return 0;
}

static __poll_t epollfs_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    struct epoll_event event;
    epoll_t *epoll = epoll_file_handle(file);

    (void)pt;
    if (!epoll)
        return EPOLLNVAL;

    mutex_lock(&epoll->lock);
    int ready = epoll_collect_ready_locked(epoll, &event, 1);
    mutex_unlock(&epoll->lock);
    return ready > 0 ? EPOLLIN : 0;
}

static loff_t epollfs_llseek(struct vfs_file *file, loff_t offset, int whence) {
    (void)file;
    (void)offset;
    (void)whence;
    return -ESPIPE;
}

static int epollfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    if (!file)
        return -EINVAL;
    file->private_data = inode ? inode->i_private : NULL;
    return 0;
}

static const struct vfs_file_operations epollfs_dir_file_ops = {
    .llseek = epollfs_llseek,
};

static const struct vfs_file_operations epollfs_file_ops = {
    .llseek = epollfs_llseek,
    .poll = epollfs_poll,
    .open = epollfs_open,
    .release = epollfs_release,
};

static struct vfs_mount *epollfs_get_internal_mount(void) {
    int ret;

    mutex_lock(&epollfs_mount_lock);
    if (!epollfs_internal_mnt) {
        ret = vfs_kern_mount("epollfs", 0, NULL, NULL, &epollfs_internal_mnt);
        if (ret < 0)
            epollfs_internal_mnt = NULL;
    }
    if (epollfs_internal_mnt)
        vfs_mntget(epollfs_internal_mnt);
    mutex_unlock(&epollfs_mount_lock);
    return epollfs_internal_mnt;
}

static int epollfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int epollfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    epollfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *root;

    if (!fc)
        return -EINVAL;

    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb)
        return -ENOMEM;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    sb->s_magic = EPOLLFS_MAGIC;
    sb->s_fs_info = fsi;
    sb->s_op = &epollfs_super_ops;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->inode = 1;
    inode->i_mode = S_IFDIR | 0700;
    inode->type = file_dir;
    inode->i_nlink = 2;
    inode->i_fop = &epollfs_dir_file_ops;

    root = vfs_d_alloc(sb, NULL, NULL);
    if (!root) {
        vfs_iput(inode);
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root, inode);
    sb->s_root = root;
    fc->sb = sb;
    return 0;
}

static void epollfs_kill_sb(struct vfs_super_block *sb) {
    if (!sb)
        return;
    free(sb->s_fs_info);
    sb->s_fs_info = NULL;
}

static const struct vfs_super_operations epollfs_super_ops = {
    .put_super = epollfs_kill_sb,
};

static struct vfs_file_system_type epollfs_fs_type = {
    .name = "epollfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = epollfs_init_fs_context,
    .get_tree = epollfs_get_tree,
};

static int epoll_create_handle_file(struct vfs_file **out_file,
                                    unsigned int open_flags,
                                    epoll_t **out_epoll) {
    struct vfs_mount *mnt;
    struct vfs_super_block *sb;
    epollfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *dentry;
    struct vfs_qstr name = {0};
    struct vfs_file *file;
    epoll_t *epoll;
    char namebuf[32];

    if (!out_file)
        return -EINVAL;

    mnt = epollfs_get_internal_mount();
    if (!mnt)
        return -ENODEV;

    epoll = calloc(1, sizeof(*epoll));
    if (!epoll) {
        vfs_mntput(mnt);
        return -ENOMEM;
    }
    mutex_init(&epoll->lock);
    llist_init_head(&epoll->watches);

    sb = mnt->mnt_sb;
    fsi = epollfs_sb_info(sb);
    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(epoll);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    spin_lock(&fsi->lock);
    inode->i_ino = ++fsi->next_ino;
    spin_unlock(&fsi->lock);
    inode->inode = inode->i_ino;
    inode->i_mode = S_IFREG | 0600;
    inode->type = file_none;
    inode->i_nlink = 1;
    inode->i_fop = &epollfs_file_ops;
    inode->i_private = epoll;

    snprintf(namebuf, sizeof(namebuf), "anon-%llu",
             (unsigned long long)inode->i_ino);
    vfs_qstr_make(&name, namebuf);
    dentry = vfs_d_alloc(sb, sb->s_root, &name);
    if (!dentry) {
        vfs_iput(inode);
        free(epoll);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    vfs_d_instantiate(dentry, inode);
    file = vfs_alloc_file(&(struct vfs_path){.mnt = mnt, .dentry = dentry},
                          O_RDONLY | (open_flags & O_NONBLOCK));
    if (!file) {
        vfs_dput(dentry);
        vfs_iput(inode);
        free(epoll);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    file->private_data = epoll;
    *out_file = file;
    if (out_epoll)
        *out_epoll = epoll;

    vfs_dput(dentry);
    vfs_iput(inode);
    vfs_mntput(mnt);
    return 0;
}

size_t epoll_create1(int flags) {
    struct vfs_file *file = NULL;
    int ret;

    ret = epoll_create_handle_file(&file, (unsigned int)flags, NULL);
    if (ret < 0)
        return (uint64_t)ret;

    ret = task_install_file(current_task, file,
                            (flags & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_close_file(file);
    return (uint64_t)ret;
}

uint64_t sys_epoll_create(int size) {
    (void)size;
    return epoll_create1(0);
}

static uint64_t do_epoll_wait(struct vfs_file *epoll_file,
                              struct epoll_event *events, int maxevents,
                              int64_t timeout_ns) {
    epoll_t *epoll;
    int ready = 0;
    bool irq_state;
    uint64_t start;
    bool infinite_timeout;

    if (!epoll_file || maxevents < 1)
        return (uint64_t)-EINVAL;

    epoll = epoll_file_handle(epoll_file);
    if (!epoll)
        return (uint64_t)-EBADF;

    irq_state = arch_interrupt_enabled();
    start = nano_time();
    infinite_timeout = timeout_ns < 0;

    do {
        arch_disable_interrupt();

        mutex_lock(&epoll->lock);
        ready = epoll_collect_ready_locked(epoll, events, maxevents);
        if (ready > 0) {
            mutex_unlock(&epoll->lock);
            break;
        }
        if (task_signal_has_deliverable(current_task)) {
            mutex_unlock(&epoll->lock);
            ready = -EINTR;
            break;
        }
        if (timeout_ns == 0) {
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
        if (task_signal_has_deliverable(current_task)) {
            epoll_disarm_waiters(waits, waits_count);
            ready = -EINTR;
            break;
        }

        int64_t wait_ns = -1;
        if (!infinite_timeout) {
            uint64_t elapsed = nano_time() - start;
            if (elapsed >= (uint64_t)timeout_ns) {
                epoll_disarm_waiters(waits, waits_count);
                break;
            }
            wait_ns = timeout_ns - (int64_t)elapsed;
        }

        int64_t block_ns = wait_ns;
        if (block_ns < 0 || block_ns > 10000000LL)
            block_ns = 10000000LL;

        arch_enable_interrupt();
        int block_reason =
            task_block(current_task, TASK_BLOCKING, block_ns, "epoll_wait");
        arch_disable_interrupt();
        epoll_disarm_waiters(waits, waits_count);
        if (block_reason == ETIMEDOUT) {
            if (infinite_timeout) {
                continue;
            }
            break;
        }
        if (block_reason != EOK) {
            ready = -EINTR;
            break;
        }
    } while (infinite_timeout || (nano_time() - start) < timeout_ns);

    if (irq_state)
        arch_enable_interrupt();
    else
        arch_disable_interrupt();

    return (uint64_t)ready;
}

static size_t epoll_ctl_file(struct vfs_file *epoll_file, int op, int fd,
                             const struct epoll_event *event) {
    struct vfs_file *target;
    epoll_t *epoll;
    epoll_watch_t *existing = NULL;
    epoll_watch_t *b, *t;
    int ret = 0;

    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_DEL && op != EPOLL_CTL_MOD)
        return (uint64_t)-EINVAL;
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) && !event)
        return (uint64_t)-EFAULT;

    epoll = epoll_file_handle(epoll_file);
    if (!epoll)
        return (uint64_t)-EBADF;

    target = task_get_file(current_task, fd);
    if (!target)
        return (uint64_t)-EBADF;

    mutex_lock(&epoll->lock);
    llist_for_each(b, t, &epoll->watches, node) {
        if (b->file == target) {
            existing = b;
            break;
        }
    }

    switch (op) {
    case EPOLL_CTL_ADD: {
        epoll_watch_t *new_watch;

        if (existing) {
            ret = -EEXIST;
            break;
        }
        new_watch = calloc(1, sizeof(*new_watch));
        if (!new_watch) {
            ret = -ENOMEM;
            break;
        }
        new_watch->file = vfs_file_get(target);
        new_watch->events = epoll_filter_events(event->events);
        new_watch->data = event->data.u64;
        new_watch->edge_trigger = (event->events & EPOLLET) != 0;
        new_watch->one_shot = (event->events & EPOLLONESHOT) != 0;
        epoll_watch_sync_seq(new_watch);
        llist_init_head(&new_watch->node);
        llist_append(&epoll->watches, &new_watch->node);
        break;
    }
    case EPOLL_CTL_DEL:
        if (!existing) {
            ret = -ENOENT;
            break;
        }
        if (existing->file)
            vfs_file_put(existing->file);
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
    vfs_file_put(target);
    return (uint64_t)ret;
}

static size_t do_epoll_pwait(struct vfs_file *epoll_file,
                             struct epoll_event *events, int maxevents,
                             int64_t timeout_ns, const sigset_t *sigmask,
                             size_t sigsetsize) {
    sigset_t origmask;

    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask, sizeof(sigset_t));
    uint64_t ret = do_epoll_wait(epoll_file, events, maxevents, timeout_ns);
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, 0, sizeof(sigset_t));
    return ret;
}

uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                        int timeout) {
    struct vfs_file *epoll_file;
    struct epoll_event *kevents;
    uint64_t ret;

    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    if (check_user_overflow((uint64_t)events,
                            (size_t)maxevents * sizeof(*events))) {
        return (uint64_t)-EFAULT;
    }

    epoll_file = task_get_file(current_task, epfd);
    if (!epoll_file)
        return (uint64_t)-EBADF;

    kevents = calloc((size_t)maxevents, sizeof(*kevents));
    if (!kevents) {
        vfs_file_put(epoll_file);
        return (uint64_t)-ENOMEM;
    }

    ret = do_epoll_wait(epoll_file, kevents, maxevents,
                        timeout < 0 ? -1 : (int64_t)timeout * 1000000LL);
    if ((int64_t)ret >= 0 &&
        copy_to_user(events, kevents, (size_t)maxevents * sizeof(*kevents))) {
        ret = (uint64_t)-EFAULT;
    }

    free(kevents);
    vfs_file_put(epoll_file);
    return ret;
}

uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    struct vfs_file *epoll_file;
    struct epoll_event k_event;
    const struct epoll_event *event_ptr = NULL;
    uint64_t ret;

    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
        check_user_overflow((uint64_t)event, sizeof(*event))) {
        return (uint64_t)-EFAULT;
    }

    epoll_file = task_get_file(current_task, epfd);
    if (!epoll_file)
        return (uint64_t)-EBADF;

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (!event || copy_from_user(&k_event, event, sizeof(k_event))) {
            vfs_file_put(epoll_file);
            return (uint64_t)-EFAULT;
        }
        event_ptr = &k_event;
    }

    ret = epoll_ctl_file(epoll_file, op, fd, event_ptr);
    vfs_file_put(epoll_file);
    return ret;
}

uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                         int timeout, sigset_t *sigmask, size_t sigsetsize) {
    struct vfs_file *epoll_file;
    struct epoll_event *kevents;
    sigset_t newmask = 0;
    const sigset_t *sigmask_ptr = NULL;
    uint64_t ret;

    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    if (check_user_overflow((uint64_t)events,
                            (size_t)maxevents * sizeof(*events))) {
        return (uint64_t)-EFAULT;
    }
    if (sigmask && sigsetsize < sizeof(sigset_t))
        return (uint64_t)-EINVAL;

    epoll_file = task_get_file(current_task, epfd);
    if (!epoll_file)
        return (uint64_t)-EBADF;

    if (sigmask) {
        if (copy_from_user(&newmask, sigmask, sizeof(newmask))) {
            vfs_file_put(epoll_file);
            return (uint64_t)-EFAULT;
        }
        sigmask_ptr = &newmask;
    }

    kevents = calloc((size_t)maxevents, sizeof(*kevents));
    if (!kevents) {
        vfs_file_put(epoll_file);
        return (uint64_t)-ENOMEM;
    }

    ret = do_epoll_pwait(epoll_file, kevents, maxevents,
                         timeout < 0 ? -1 : (int64_t)timeout * 1000000LL,
                         sigmask_ptr, sigsetsize);
    if ((int64_t)ret >= 0 &&
        copy_to_user(events, kevents, (size_t)maxevents * sizeof(*kevents))) {
        ret = (uint64_t)-EFAULT;
    }

    free(kevents);
    vfs_file_put(epoll_file);
    return ret;
}

uint64_t sys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                          struct timespec *timeout, sigset_t *sigmask,
                          size_t sigsetsize) {
    struct vfs_file *epoll_file;
    struct epoll_event *kevents;
    sigset_t newmask = 0;
    const sigset_t *sigmask_ptr = NULL;
    int64_t timeout_ns = -1;
    uint64_t ret;

    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    if (check_user_overflow((uint64_t)events,
                            (size_t)maxevents * sizeof(*events))) {
        return (uint64_t)-EFAULT;
    }
    if (sigmask && sigsetsize < sizeof(sigset_t))
        return (uint64_t)-EINVAL;

    epoll_file = task_get_file(current_task, epfd);
    if (!epoll_file)
        return (uint64_t)-EBADF;

    if (timeout) {
        struct timespec ts;
        if (copy_from_user(&ts, timeout, sizeof(ts))) {
            vfs_file_put(epoll_file);
            return (uint64_t)-EFAULT;
        }
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL) {
            vfs_file_put(epoll_file);
            return (uint64_t)-EINVAL;
        }
        timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
    }

    if (sigmask) {
        if (copy_from_user(&newmask, sigmask, sizeof(newmask))) {
            vfs_file_put(epoll_file);
            return (uint64_t)-EFAULT;
        }
        sigmask_ptr = &newmask;
    }

    kevents = calloc((size_t)maxevents, sizeof(*kevents));
    if (!kevents) {
        vfs_file_put(epoll_file);
        return (uint64_t)-ENOMEM;
    }

    ret = do_epoll_pwait(epoll_file, kevents, maxevents, timeout_ns,
                         sigmask_ptr, sigsetsize);
    if ((int64_t)ret >= 0 &&
        copy_to_user(events, kevents, (size_t)maxevents * sizeof(*kevents))) {
        ret = (uint64_t)-EFAULT;
    }

    free(kevents);
    vfs_file_put(epoll_file);
    return ret;
}

uint64_t sys_epoll_create1(int flags) { return epoll_create1(flags); }

void epoll_init(void) {
    mutex_init(&epollfs_mount_lock);
    vfs_register_filesystem(&epollfs_fs_type);
}
