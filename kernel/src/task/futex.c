#include <task/futex.h>
#include <fs/fs_syscall.h>

spinlock_t futex_lock;
struct futex_wait futex_wait_list = {0, 0, NULL, NULL, 0};

typedef struct futex_key {
    uint64_t addr;
    uintptr_t ctx;
} futex_key_t;

static bool futex_key_equal(const struct futex_wait *wait,
                            const futex_key_t *key) {
    return wait->key_addr == key->addr && wait->key_ctx == key->ctx;
}

static uint64_t futex_build_key(int *uaddr, bool is_private, futex_key_t *key) {
    if (is_private) {
        if (!current_task || !current_task->arch_context ||
            !current_task->arch_context->mm)
            return (uint64_t)-EFAULT;

        key->addr = (uint64_t)uaddr;
        key->ctx = (uintptr_t)current_task->arch_context->mm;
        return 0;
    }

    uint64_t phys =
        translate_address(get_current_page_dir(true), (uint64_t)uaddr);
    if (!phys)
        return (uint64_t)-EFAULT;

    key->addr = phys;
    key->ctx = 0;
    return 0;
}

static void futex_enqueue_locked(struct futex_wait *wait) {
    struct futex_wait *curr = &futex_wait_list;
    while (curr->next)
        curr = curr->next;
    curr->next = wait;
}

static bool futex_dequeue_locked(struct futex_wait *target) {
    struct futex_wait *prev = &futex_wait_list;
    struct futex_wait *curr = futex_wait_list.next;

    while (curr) {
        if (curr == target) {
            prev->next = curr->next;
            curr->next = NULL;
            return true;
        }
        prev = curr;
        curr = curr->next;
    }

    return false;
}

static int futex_wake_locked(const futex_key_t *key, int val, uint32_t bitset) {
    if (val <= 0)
        return 0;

    struct futex_wait *prev = &futex_wait_list;
    struct futex_wait *curr = futex_wait_list.next;
    int woke = 0;

    while (curr) {
        struct futex_wait *next = curr->next;

        if (!curr->task || curr->task->state == TASK_DIED) {
            prev->next = next;
            curr->next = NULL;
            curr = next;
            continue;
        }

        if (futex_key_equal(curr, key) && (curr->bitset & bitset) != 0 &&
            woke < val) {
            prev->next = next;
            curr->next = NULL;
            task_unblock(curr->task, EOK);
            woke++;
            curr = next;
            continue;
        }

        prev = curr;
        curr = next;
    }

    return woke;
}

static uint64_t futex_now_ns(bool realtime) {
    if (!realtime)
        return nano_time();

    tm now_tm;
    time_read(&now_tm);
    return (uint64_t)mktime(&now_tm) * 1000000000ULL;
}

static uint64_t sys_futex_wait(int *uaddr, const futex_key_t *key, int val,
                               const struct timespec *timeout, uint32_t bitset,
                               bool absolute_timeout, bool realtime_clock) {
    if (bitset == 0)
        return (uint64_t)-EINVAL;

    int64_t tmo = -1;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= 1000000000L) {
            return (uint64_t)-EINVAL;
        }
        int64_t req = timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
        if (!absolute_timeout) {
            tmo = req;
        } else {
            uint64_t now_ns = futex_now_ns(realtime_clock);
            if ((uint64_t)req <= now_ns)
                return (uint64_t)-ETIMEDOUT;
            tmo = req - now_ns;
        }
    }

    struct futex_wait wait = {
        .key_addr = key->addr,
        .key_ctx = key->ctx,
        .task = current_task,
        .next = NULL,
        .bitset = bitset,
    };

    spin_lock(&futex_lock);
    if (*(volatile int *)uaddr != val) {
        spin_unlock(&futex_lock);
        return (uint64_t)-EAGAIN;
    }
    if (timeout && tmo == 0) {
        spin_unlock(&futex_lock);
        return (uint64_t)-ETIMEDOUT;
    }
    futex_enqueue_locked(&wait);
    spin_unlock(&futex_lock);

    int reason = task_block(current_task, TASK_BLOCKING, tmo, "futex_wait");

    spin_lock(&futex_lock);
    futex_dequeue_locked(&wait);
    spin_unlock(&futex_lock);

    if (reason == ETIMEDOUT)
        return (uint64_t)-ETIMEDOUT;
    if (reason != EOK)
        return (uint64_t)-EINTR;

    return 0;
}

static uint64_t sys_futex_wake_key(const futex_key_t *key, int val,
                                   uint32_t bitset) {
    if (bitset == 0)
        return (uint64_t)-EINVAL;

    spin_lock(&futex_lock);
    int count = futex_wake_locked(key, val, bitset);
    spin_unlock(&futex_lock);
    return count;
}

uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset) {
    if (bitset == 0)
        return (uint64_t)-EINVAL;

    if (!current_task || !current_task->arch_context ||
        !current_task->arch_context->mm)
        return 0;

    futex_key_t key = {
        .addr = addr,
        .ctx = (uintptr_t)current_task->arch_context->mm,
    };
    return sys_futex_wake_key(&key, val, bitset);
}

uint64_t sys_futex(int *uaddr, int op, int val, const struct timespec *timeout,
                   int *uaddr2, int val3) {
    if (!uaddr || check_user_overflow((uint64_t)uaddr, sizeof(int)) ||
        check_unmapped((uint64_t)uaddr, sizeof(int)))
        return (uint64_t)-EFAULT;

    bool is_private = (op & FUTEX_PRIVATE_FLAG) != 0;

    switch (op & FUTEX_CMD_MASK) {
    case FUTEX_WAIT: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wait(uaddr, &key, val, timeout, 0xFFFFFFFF, false,
                              false);
    }
    case FUTEX_WAKE: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wake_key(&key, val, 0xFFFFFFFF);
    }
    case FUTEX_WAIT_BITSET: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wait(uaddr, &key, val, timeout, (uint32_t)val3, true,
                              (op & FUTEX_CLOCK_REALTIME) != 0);
    }
    case FUTEX_WAKE_BITSET: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wake_key(&key, val, (uint32_t)val3);
    }
    case FUTEX_WAKE_OP: {
        int op_type = (val3 >> 28) & 0xf;
        int cmp_type = (val3 >> 24) & 0xf;
        int oparg = (val3 >> 12) & 0xfff;
        int cmparg = val3 & 0xfff;

        if (oparg & 0x800)
            oparg |= 0xFFFFF000;
        if (cmparg & 0x800)
            cmparg |= 0xFFFFF000;

        if (op_type & FUTEX_OP_OPARG_SHIFT) {
            oparg = 1 << (oparg & 0x1f);
            op_type &= ~FUTEX_OP_OPARG_SHIFT;
        }

        if (!uaddr2 || check_user_overflow((uint64_t)uaddr2, sizeof(int)) ||
            check_unmapped((uint64_t)uaddr2, sizeof(int)))
            return (uint64_t)-EFAULT;

        futex_key_t key1;
        futex_key_t key2;
        uint64_t ret = futex_build_key(uaddr, is_private, &key1);
        if ((int64_t)ret < 0)
            return ret;
        ret = futex_build_key(uaddr2, is_private, &key2);
        if ((int64_t)ret < 0)
            return ret;

        spin_lock(&futex_lock);

        int oldval = *uaddr2;
        int newval;

        switch (op_type) {
        case FUTEX_OP_SET:
            newval = oparg;
            break;
        case FUTEX_OP_ADD:
            newval = oldval + oparg;
            break;
        case FUTEX_OP_OR:
            newval = oldval | oparg;
            break;
        case FUTEX_OP_ANDN:
            newval = oldval & ~oparg;
            break;
        case FUTEX_OP_XOR:
            newval = oldval ^ oparg;
            break;
        default:
            spin_unlock(&futex_lock);
            return (uint64_t)-ENOSYS;
        }
        *uaddr2 = newval;

        int ret_count = futex_wake_locked(&key1, val, 0xFFFFFFFF);

        bool wake_uaddr2 = false;
        switch (cmp_type) {
        case FUTEX_OP_CMP_EQ:
            wake_uaddr2 = (oldval == cmparg);
            break;
        case FUTEX_OP_CMP_NE:
            wake_uaddr2 = (oldval != cmparg);
            break;
        case FUTEX_OP_CMP_LT:
            wake_uaddr2 = (oldval < cmparg);
            break;
        case FUTEX_OP_CMP_LE:
            wake_uaddr2 = (oldval <= cmparg);
            break;
        case FUTEX_OP_CMP_GT:
            wake_uaddr2 = (oldval > cmparg);
            break;
        case FUTEX_OP_CMP_GE:
            wake_uaddr2 = (oldval >= cmparg);
            break;
        default:
            break;
        }

        if (wake_uaddr2) {
            int val2 = (int)(uintptr_t)timeout;
            ret_count += futex_wake_locked(&key2, val2, 0xFFFFFFFF);
        }

        spin_unlock(&futex_lock);
        return ret_count;
    }
    case FUTEX_LOCK_PI: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;

        int64_t tmo = -1;
        if (timeout) {
            if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
                timeout->tv_nsec >= 1000000000L) {
                return (uint64_t)-EINVAL;
            }
            tmo = timeout->tv_sec * 1000000000LL + timeout->tv_nsec;
        }

        struct futex_wait wait = {
            .key_addr = key.addr,
            .key_ctx = key.ctx,
            .task = current_task,
            .next = NULL,
            .bitset = (uint32_t)val3 ? (uint32_t)val3 : 0xFFFFFFFF,
        };

    retry:
        spin_lock(&futex_lock);
        if ((*uaddr & INT32_MAX) == 0) {
            *uaddr = current_task->pid;
            spin_unlock(&futex_lock);
            return 0;
        } else {
            if (timeout && tmo == 0) {
                spin_unlock(&futex_lock);
                return (uint64_t)-ETIMEDOUT;
            }
            futex_enqueue_locked(&wait);
            spin_unlock(&futex_lock);

            int reason =
                task_block(current_task, TASK_BLOCKING, tmo, "futex_lock_pi");

            spin_lock(&futex_lock);
            futex_dequeue_locked(&wait);
            spin_unlock(&futex_lock);

            if (reason == ETIMEDOUT)
                return (uint64_t)-ETIMEDOUT;
            if (reason != EOK)
                return (uint64_t)-EINTR;

            goto retry;
        }
    }
    case FUTEX_UNLOCK_PI: {
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;

        spin_lock(&futex_lock);
        if ((*uaddr & INT32_MAX) != current_task->pid) {
            spin_unlock(&futex_lock);
            return (uint64_t)-EPERM;
        }
        *uaddr = 0;
        futex_wake_locked(&key, 1, 0xFFFFFFFF);
        spin_unlock(&futex_lock);
        return 0;
    }
    case FUTEX_REQUEUE:
    case FUTEX_CMP_REQUEUE: {
        if (!uaddr2 || check_user_overflow((uint64_t)uaddr2, sizeof(int)) ||
            check_unmapped((uint64_t)uaddr2, sizeof(int)))
            return (uint64_t)-EFAULT;

        int nr_requeue = (int)(uintptr_t)timeout;
        if (val < 0 || nr_requeue < 0)
            return (uint64_t)-EINVAL;

        futex_key_t src_key;
        futex_key_t dst_key;
        uint64_t ret = futex_build_key(uaddr, is_private, &src_key);
        if ((int64_t)ret < 0)
            return ret;
        ret = futex_build_key(uaddr2, is_private, &dst_key);
        if ((int64_t)ret < 0)
            return ret;

        spin_lock(&futex_lock);

        if ((op & FUTEX_CMD_MASK) == FUTEX_CMP_REQUEUE &&
            *(volatile int *)uaddr != val3) {
            spin_unlock(&futex_lock);
            return (uint64_t)-EAGAIN;
        }

        int wake_count = futex_wake_locked(&src_key, val, 0xFFFFFFFF);
        int requeue_count = 0;

        if (nr_requeue > 0) {
            struct futex_wait *curr = futex_wait_list.next;
            while (curr && requeue_count < nr_requeue) {
                if (!curr->task || curr->task->state == TASK_DIED) {
                    struct futex_wait *dead = curr;
                    curr = curr->next;
                    futex_dequeue_locked(dead);
                    continue;
                }
                if (futex_key_equal(curr, &src_key)) {
                    curr->key_addr = dst_key.addr;
                    curr->key_ctx = dst_key.ctx;
                    requeue_count++;
                }
                curr = curr->next;
            }
        }

        spin_unlock(&futex_lock);
        return wake_count + requeue_count;
    }
    default:
        printk("futex: Unsupported op: %d\n", op);
        return (uint64_t)-ENOSYS;
    }
}

void futex_init() { spin_init(&futex_lock); }
