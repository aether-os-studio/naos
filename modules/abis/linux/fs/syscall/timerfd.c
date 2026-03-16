#include <fs/fs_syscall.h>
#include <fs/proc.h>
#include <arch/arch.h>
#include <boot/boot.h>
#include <irq/softirq.h>
#include <libs/klibc.h>
#include <libs/rbtree.h>
#include <task/signal.h>
#include <task/task_syscall.h>

int timerfdfs_id = 0;
static rb_root_t timerfd_mono_root = RB_ROOT_INIT;
static rb_root_t timerfd_real_root = RB_ROOT_INIT;
static spinlock_t timerfd_mono_lock = SPIN_INIT;
static spinlock_t timerfd_real_lock = SPIN_INIT;

static uint64_t get_current_time_ns(int clock_type);

static inline spinlock_t *timerfd_tree_lock_for_clock(int clock_type) {
    return clock_type == CLOCK_REALTIME ? &timerfd_real_lock
                                        : &timerfd_mono_lock;
}

static inline rb_root_t *timerfd_root_for_clock(int clock_type) {
    return clock_type == CLOCK_REALTIME ? &timerfd_real_root
                                        : &timerfd_mono_root;
}

static inline int timerfd_cmp(timerfd_t *left, timerfd_t *right) {
    if (left->timer.expires < right->timer.expires)
        return -1;
    if (left->timer.expires > right->timer.expires)
        return 1;
    if ((uint64_t)(uintptr_t)left->node < (uint64_t)(uintptr_t)right->node)
        return -1;
    if ((uint64_t)(uintptr_t)left->node > (uint64_t)(uintptr_t)right->node)
        return 1;
    return 0;
}

static inline timerfd_t *timerfd_first_locked(rb_root_t *root) {
    rb_node_t *first = rb_first(root);
    return first ? rb_entry(first, timerfd_t, timeout_node) : NULL;
}

static void timerfd_timeout_remove_locked(timerfd_t *tfd) {
    if (!tfd || !tfd->timeout_queued)
        return;

    rb_erase(&tfd->timeout_node, timerfd_root_for_clock(tfd->timer.clock_type));
    memset(&tfd->timeout_node, 0, sizeof(tfd->timeout_node));
    tfd->timeout_queued = false;
}

static void timerfd_timeout_add_locked(timerfd_t *tfd) {
    if (!tfd || !tfd->node || !tfd->timer.expires || tfd->timeout_queued)
        return;

    rb_root_t *root = timerfd_root_for_clock(tfd->timer.clock_type);
    rb_node_t **slot = &root->rb_node;
    rb_node_t *parent = NULL;

    while (*slot) {
        timerfd_t *curr = rb_entry(*slot, timerfd_t, timeout_node);
        int cmp = timerfd_cmp(tfd, curr);
        parent = *slot;
        if (cmp < 0)
            slot = &(*slot)->rb_left;
        else
            slot = &(*slot)->rb_right;
    }

    tfd->timeout_node.rb_left = NULL;
    tfd->timeout_node.rb_right = NULL;
    rb_set_parent(&tfd->timeout_node, parent);
    rb_set_color(&tfd->timeout_node, KRB_RED);
    *slot = &tfd->timeout_node;
    rb_insert_color(&tfd->timeout_node, root);
    tfd->timeout_queued = true;
}

static bool timerfd_update_due_locked(timerfd_t *tfd, uint64_t now) {
    if (!tfd || !tfd->timer.expires || now < tfd->timer.expires)
        return false;

    if (tfd->timer.interval) {
        uint64_t delta = now - tfd->timer.expires;
        uint64_t periods = delta / tfd->timer.interval + 1;
        tfd->count += periods;
        tfd->timer.expires += periods * tfd->timer.interval;
    } else {
        tfd->count++;
        tfd->timer.expires = 0;
    }

    return true;
}

static bool timerfd_update_due_requeue_locked(timerfd_t *tfd, uint64_t now) {
    if (!tfd || !tfd->timer.expires || now < tfd->timer.expires)
        return false;

    bool was_queued = tfd->timeout_queued;
    if (was_queued)
        timerfd_timeout_remove_locked(tfd);

    bool changed = timerfd_update_due_locked(tfd, now);
    timerfd_timeout_add_locked(tfd);
    return changed;
}

static inline void timerfd_snapshot_state(timerfd_t *tfd, int *clock_type,
                                          uint64_t *expires, uint64_t *count) {
    spin_lock(&tfd->lock);
    if (clock_type)
        *clock_type = tfd->timer.clock_type;
    if (expires)
        *expires = tfd->timer.expires;
    if (count)
        *count = tfd->count;
    spin_unlock(&tfd->lock);
}

static inline void timerfd_lock_pair(timerfd_t *tfd) {
    spin_lock(timerfd_tree_lock_for_clock(tfd->timer.clock_type));
    spin_lock(&tfd->lock);
}

static inline void timerfd_unlock_pair(timerfd_t *tfd) {
    spin_unlock(&tfd->lock);
    spin_unlock(timerfd_tree_lock_for_clock(tfd->timer.clock_type));
}

static bool timerfd_refresh_due(timerfd_t *tfd, int clock_type, uint64_t now,
                                uint64_t *count, uint64_t *expires) {
    if (!tfd)
        return false;

    spinlock_t *tree_lock = timerfd_tree_lock_for_clock(clock_type);
    bool changed = false;

    spin_lock(tree_lock);
    spin_lock(&tfd->lock);
    if (tfd->timer.clock_type == clock_type && tfd->timer.expires &&
        now >= tfd->timer.expires) {
        changed = timerfd_update_due_requeue_locked(tfd, now);
    }
    if (count)
        *count = tfd->count;
    if (expires)
        *expires = tfd->timer.expires;
    spin_unlock(&tfd->lock);
    spin_unlock(tree_lock);

    return changed;
}

void timerfd_check_wakeup(void) {
    bool raise = false;
    uint64_t now_mono = nano_time();

    spin_lock(&timerfd_mono_lock);
    timerfd_t *mono = timerfd_first_locked(&timerfd_mono_root);
    if (mono && mono->timer.expires <= now_mono) {
        raise = true;
    }
    spin_unlock(&timerfd_mono_lock);

    if (!raise) {
        uint64_t now_real = get_current_time_ns(CLOCK_REALTIME);

        spin_lock(&timerfd_real_lock);
        timerfd_t *real = timerfd_first_locked(&timerfd_real_root);
        if (real && real->timer.expires <= now_real)
            raise = true;
        spin_unlock(&timerfd_real_lock);
    }

    if (raise)
        softirq_raise(SOFTIRQ_TIMERFD);
}

void timerfd_softirq(void) {
    while (true) {
        bool progressed = false;
        int clocks[2] = {CLOCK_MONOTONIC, CLOCK_REALTIME};

        for (int i = 0; i < 2; i++) {
            int clock_type = clocks[i];
            uint64_t now = get_current_time_ns(clock_type);
            spinlock_t *tree_lock = timerfd_tree_lock_for_clock(clock_type);

            while (true) {
                vfs_node_t notify_node = NULL;

                spin_lock(tree_lock);
                timerfd_t *tfd =
                    timerfd_first_locked(timerfd_root_for_clock(clock_type));
                if (!tfd || tfd->timer.expires > now) {
                    spin_unlock(tree_lock);
                    break;
                }

                spin_lock(&tfd->lock);
                if (tfd->timer.expires && tfd->timer.expires <= now) {
                    timerfd_timeout_remove_locked(tfd);
                    if (timerfd_update_due_locked(tfd, now)) {
                        notify_node = tfd->node;
                        if (notify_node)
                            vfs_node_ref_get(notify_node);
                    }
                    timerfd_timeout_add_locked(tfd);
                    progressed = true;
                }
                spin_unlock(&tfd->lock);
                spin_unlock(tree_lock);

                if (!notify_node)
                    continue;

                vfs_poll_notify(notify_node, EPOLLIN);
                vfs_node_ref_put(notify_node, NULL);
            }
        }

        if (!progressed)
            return;
    }
}

uint64_t sys_timerfd_create(int clockid, int flags) {
    if (flags & ~(TFD_NONBLOCK | TFD_CLOEXEC))
        return -EINVAL;

    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    timerfd_t *tfd = malloc(sizeof(timerfd_t));
    if (!tfd)
        return -ENOMEM;
    memset(tfd, 0, sizeof(timerfd_t));
    spin_init(&tfd->lock);
    tfd->timer.clock_type = clockid;

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->refcount++;
    node->type = file_stream;
    node->fsid = timerfdfs_id;
    node->handle = tfd;
    tfd->node = node;

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

        fd_t *new_fd = fd_create(node, O_RDONLY | (flags & TFD_NONBLOCK),
                                 !!(flags & TFD_CLOEXEC));
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
        return ret;
    }

    return fd;
}

// 统一的当前时间获取函数
static uint64_t get_current_time_ns(int clock_type) {
    if (clock_type == CLOCK_MONOTONIC) {
        return nano_time(); // 单调时钟，直接返回纳秒
    } else {                // CLOCK_REALTIME
        return boot_get_boottime() * 1000000000ULL + nano_time();
    }
}

uint64_t sys_timerfd_settime(int fd, int flags,
                             const struct itimerspec *new_value,
                             struct itimerspec *old_value) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;
    if (!new_value)
        return -EINVAL;
    if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET))
        return -EINVAL;
    if (new_value->it_value.tv_sec < 0 || new_value->it_value.tv_nsec < 0 ||
        new_value->it_interval.tv_sec < 0 ||
        new_value->it_interval.tv_nsec < 0 ||
        new_value->it_value.tv_nsec >= 1000000000L ||
        new_value->it_interval.tv_nsec >= 1000000000L) {
        return -EINVAL;
    }

    vfs_node_t node = current_task->fd_info->fds[fd]->node;
    timerfd_t *tfd = node->handle;
    if (!tfd)
        return -EBADF;

    int clock_type = tfd->timer.clock_type;
    bool notify_readable = false;
    bool raise_softirq = false;
    bool have_now = false;
    uint64_t now = 0;
    uint64_t interval = new_value->it_interval.tv_sec * 1000000000ULL +
                        (uint64_t)new_value->it_interval.tv_nsec;
    uint64_t value = new_value->it_value.tv_sec * 1000000000ULL +
                     (uint64_t)new_value->it_value.tv_nsec;

    if (old_value || (!(flags & TFD_TIMER_ABSTIME) && value != 0)) {
        now = get_current_time_ns(clock_type);
        have_now = true;
    }

    spin_lock(timerfd_tree_lock_for_clock(clock_type));
    spin_lock(&tfd->lock);
    timerfd_timeout_remove_locked(tfd);

    if (old_value) {
        uint64_t remaining =
            tfd->timer.expires > now ? tfd->timer.expires - now : 0;

        old_value->it_interval.tv_sec = tfd->timer.interval / 1000000000ULL;
        old_value->it_interval.tv_nsec = tfd->timer.interval % 1000000000ULL;
        old_value->it_value.tv_sec = remaining / 1000000000ULL;
        old_value->it_value.tv_nsec = remaining % 1000000000ULL;
    }

    uint64_t expires = 0;

    if (flags & TFD_TIMER_ABSTIME) {
        expires = value;
    } else {
        expires = value ? now + value : 0;
    }

    tfd->timer.expires = expires;
    tfd->timer.interval = interval;
    if (value == 0) {
        tfd->count = 0;
    }
    timerfd_timeout_add_locked(tfd);
    if (tfd->timer.expires && have_now && tfd->timer.expires <= now)
        raise_softirq = true;
    notify_readable = tfd->count > 0;
    spin_unlock(&tfd->lock);
    spin_unlock(timerfd_tree_lock_for_clock(clock_type));

    if (notify_readable)
        vfs_poll_notify(node, EPOLLIN);
    vfs_poll_notify(node, EPOLLOUT);
    if (raise_softirq)
        softirq_raise(SOFTIRQ_TIMERFD);

    return 0;
}

bool timerfd_close(vfs_node_t node) {
    timerfd_t *tfd = node ? node->handle : NULL;
    if (!tfd)
        return true;

    timerfd_lock_pair(tfd);
    timerfd_timeout_remove_locked(tfd);
    timerfd_unlock_pair(tfd);

    free(tfd);
    return true;
}

int timerfd_poll(vfs_node_t node, size_t events) {
    timerfd_t *tfd = node ? node->handle : NULL;
    if (!tfd)
        return EPOLLNVAL;

    int revents = 0;
    int clock_type = CLOCK_MONOTONIC;
    uint64_t expires = 0;
    uint64_t count = 0;

    timerfd_snapshot_state(tfd, &clock_type, &expires, &count);
    if (count == 0 && expires) {
        uint64_t now = get_current_time_ns(clock_type);
        if (now >= expires)
            timerfd_refresh_due(tfd, clock_type, now, &count, &expires);
    }

    if ((events & EPOLLIN) && count > 0)
        revents |= EPOLLIN;

    return revents;
}

ssize_t timerfd_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *file = fd->node->handle;
    timerfd_t *tfd = file;

    for (;;) {
        uint64_t count = 0;
        uint64_t expires = 0;
        int clock_type = CLOCK_MONOTONIC;
        uint64_t now = 0;

        timerfd_snapshot_state(tfd, &clock_type, &expires, &count);

        if (count == 0 && expires) {
            now = get_current_time_ns(clock_type);
            if (now >= expires)
                timerfd_refresh_due(tfd, clock_type, now, &count, &expires);
        }

        if (count != 0)
            break;

        if (expires == 0) {
            if (fd_get_flags(fd) & O_NONBLOCK) {
                return -EAGAIN;
            } else {
                vfs_poll_wait_t wait;
                vfs_poll_wait_init(&wait, current_task,
                                   EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);
                vfs_poll_wait_arm(fd->node, &wait);
                int reason = vfs_poll_wait_sleep(fd->node, &wait, 10000000LL,
                                                 "timerfd_read_unarmed");
                vfs_poll_wait_disarm(&wait);
                if (reason != EOK && reason != ETIMEDOUT)
                    return -EINTR;
                continue;
            }
        }

        if (now < expires && !(fd_get_flags(fd) & O_NONBLOCK)) {
            int64_t wait_ns = (int64_t)(expires - now);
            int reason = task_block(current_task, TASK_BLOCKING, wait_ns,
                                    "timerfd_read");
            if (reason != EOK && reason != ETIMEDOUT)
                return -EINTR;
            continue;
        }

        if (now < expires && (fd_get_flags(fd) & O_NONBLOCK)) {
            return -EAGAIN;
        }
    }

    if (size < sizeof(uint64_t))
        return -EINVAL;

    spin_lock(&tfd->lock);
    uint64_t count = tfd->count;
    tfd->count = 0;
    spin_unlock(&tfd->lock);

    *(uint64_t *)addr = count;
    vfs_poll_notify(fd->node, EPOLLOUT);

    return sizeof(uint64_t);
}

#define TFD_IOC_SET_TICKS _IOW('T', 0, uint64_t)

int timerfd_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    timerfd_t *tfd = node ? node->handle : NULL;
    if (!tfd)
        return -EBADF;
    switch (cmd) {
    case TFD_IOC_SET_TICKS:
        spin_lock(&tfd->lock);
        tfd->count = arg;
        spin_unlock(&tfd->lock);
        if (tfd->node)
            vfs_poll_notify(tfd->node, EPOLLIN);
        return 0;

    default:
        printk("timerfd_ioctl: Unsupported cmd %#018lx\n", cmd);
        return -ENOSYS;
    }
}

static vfs_operations_t timerfd_callbacks = {
    .close = timerfd_close,
    .read = timerfd_read,
    .ioctl = timerfd_ioctl,
    .poll = timerfd_poll,

    .free_handle = vfs_generic_free_handle,
};

fs_t timefdfs = {
    .name = "timefdfs",
    .magic = 0,
    .ops = &timerfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void timerfd_init() {
    spin_init(&timerfd_mono_lock);
    spin_init(&timerfd_real_lock);
    timerfd_mono_root = RB_ROOT_INIT;
    timerfd_real_root = RB_ROOT_INIT;
    softirq_register(SOFTIRQ_TIMERFD, timerfd_softirq);
    timerfdfs_id = vfs_regist(&timefdfs);
}
