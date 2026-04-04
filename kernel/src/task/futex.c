#include <boot/boot.h>
#include <task/futex.h>
#include <task/task_syscall.h>

#define FUTEX_BUCKET_BITS 8U
#define FUTEX_BUCKET_COUNT (1U << FUTEX_BUCKET_BITS)

typedef struct futex_bucket {
    spinlock_t lock;
    struct futex_wait *head;
    struct futex_wait *tail;
} futex_bucket_t;

static futex_bucket_t futex_buckets[FUTEX_BUCKET_COUNT];

uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset);

#define FUTEX_WAITERS 0x80000000U
#define FUTEX_OWNER_DIED 0x40000000U
#define FUTEX_TID_MASK 0x3FFFFFFFU
#define ROBUST_LIST_LIMIT 2048

struct robust_list {
    struct robust_list *next;
};

struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};

typedef struct futex_key {
    uint64_t addr;
    uintptr_t ctx;
} futex_key_t;

static inline uint32_t futex_bucket_id_for_key(const futex_key_t *key) {
    uint64_t hash;

    if (!key)
        return 0;

    hash = key->addr;
    hash ^= key->ctx + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    return (uint32_t)(hash & (FUTEX_BUCKET_COUNT - 1));
}

static inline futex_bucket_t *futex_bucket_for_id(uint32_t bucket_id) {
    return &futex_buckets[bucket_id & (FUTEX_BUCKET_COUNT - 1)];
}

static inline futex_bucket_t *futex_bucket_for_key(const futex_key_t *key,
                                                   uint32_t *bucket_id_out) {
    uint32_t bucket_id = futex_bucket_id_for_key(key);

    if (bucket_id_out)
        *bucket_id_out = bucket_id;
    return futex_bucket_for_id(bucket_id);
}

static uint64_t futex_build_key_for_task(task_t *task, int *uaddr,
                                         bool is_private, futex_key_t *key) {
    if (is_private) {
        if (!task || !task->arch_context || !task->mm)
            return (uint64_t)-EFAULT;

        key->addr = (uint64_t)uaddr;
        key->ctx = (uintptr_t)task->mm;
        return 0;
    }

    if (!task || !task->mm)
        return (uint64_t)-EFAULT;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t phys = translate_address(pgdir, (uint64_t)uaddr);
    if (!phys)
        return (uint64_t)-EFAULT;

    key->addr = phys;
    key->ctx = 0;
    return 0;
}

static uint64_t sys_futex_wake_key(const futex_key_t *key, int val,
                                   uint32_t bitset);

static void futex_wake_task_addr(task_t *task, int *uaddr, int val,
                                 uint32_t bitset) {
    futex_key_t key;
    if ((int64_t)futex_build_key_for_task(task, uaddr, true, &key) >= 0)
        sys_futex_wake_key(&key, val, bitset);
    if ((int64_t)futex_build_key_for_task(task, uaddr, false, &key) >= 0)
        sys_futex_wake_key(&key, val, bitset);
}

static void futex_cleanup_robust_word(task_t *task, uint64_t futex_uaddr) {
    int word = 0;
    if (read_task_user_memory(task, futex_uaddr, &word, sizeof(word)) < 0)
        return;

    if ((word & FUTEX_TID_MASK) != (int)task->pid)
        return;

    int new_word = (word & (int)FUTEX_WAITERS) | (int)FUTEX_OWNER_DIED;
    if (write_task_user_memory(task, futex_uaddr, &new_word, sizeof(new_word)) <
        0) {
        return;
    }

    if (word & (int)FUTEX_WAITERS)
        futex_wake_task_addr(task, (int *)futex_uaddr, 1, 0xFFFFFFFF);
}

static void futex_cleanup_robust_entry(task_t *task,
                                       const struct robust_list_head *head,
                                       uint64_t entry_addr) {
    if (!entry_addr)
        return;

    intptr_t futex_offset = (intptr_t)head->futex_offset;
    uint64_t futex_uaddr = entry_addr;
    if (futex_offset < 0) {
        uint64_t delta = (uint64_t)(-futex_offset);
        if (delta > entry_addr)
            return;
        futex_uaddr -= delta;
    } else {
        uint64_t delta = (uint64_t)futex_offset;
        if (delta > UINT64_MAX - entry_addr)
            return;
        futex_uaddr += delta;
    }

    futex_cleanup_robust_word(task, futex_uaddr);
}

static void futex_cleanup_robust_list(task_t *task) {
    if (!task || !task->robust_list_head ||
        task->robust_list_len < sizeof(struct robust_list_head)) {
        return;
    }

    uint64_t head_addr = (uint64_t)task->robust_list_head;
    struct robust_list_head head;
    if (read_task_user_memory(task, head_addr, &head, sizeof(head)) < 0)
        return;

    uint64_t entry_addr = (uint64_t)head.list.next;
    for (size_t count = 0;
         entry_addr && entry_addr != head_addr && count < ROBUST_LIST_LIMIT;
         count++) {
        struct robust_list entry;
        if (read_task_user_memory(task, entry_addr, &entry, sizeof(entry)) < 0)
            break;

        futex_cleanup_robust_entry(task, &head, entry_addr);
        entry_addr = (uint64_t)entry.next;
    }

    uint64_t pending_addr = (uint64_t)head.list_op_pending;
    if (pending_addr && pending_addr != head_addr)
        futex_cleanup_robust_entry(task, &head, pending_addr);
}

int futex_on_exit_task(task_t *task) {
    for (uint32_t bucket_id = 0; bucket_id < FUTEX_BUCKET_COUNT; bucket_id++) {
        futex_bucket_t *bucket = futex_bucket_for_id(bucket_id);
        spin_lock(&bucket->lock);

        struct futex_wait *prev = NULL;
        struct futex_wait *curr = bucket->head;
        while (curr) {
            struct futex_wait *next = curr->next;

            if (curr->task != task) {
                prev = curr;
                curr = next;
                continue;
            }

            if (prev)
                prev->next = next;
            else
                bucket->head = next;

            if (bucket->tail == curr)
                bucket->tail = prev;

            curr->next = NULL;
            curr = next;
        }

        spin_unlock(&bucket->lock);
    }

    futex_cleanup_robust_list(task);

    if (task->tidptr) {
        int clear_tid = 0;
        write_task_user_memory(task, (uint64_t)task->tidptr, &clear_tid,
                               sizeof(clear_tid));
        futex_wake_task_addr(task, task->tidptr, INT32_MAX, 0xFFFFFFFF);
    }

    return 0;
}

static bool futex_key_equal(const struct futex_wait *wait,
                            const futex_key_t *key) {
    return wait->key_addr == key->addr && wait->key_ctx == key->ctx;
}

static uint64_t futex_build_key(int *uaddr, bool is_private, futex_key_t *key) {
    return futex_build_key_for_task(current_task, uaddr, is_private, key);
}

static bool futex_prefault_user_word(int *uaddr, bool write) {
    if (!uaddr || !current_task || !current_task->mm)
        return false;

    uint64_t *pgdir = get_current_page_dir(true);
    return user_translate_or_fault(pgdir, (uint64_t)uaddr, write) != 0;
}

static bool futex_read_user_word(int *uaddr, int *value) {
    if (!uaddr || !value)
        return false;

    return read_task_user_memory(current_task, (uint64_t)uaddr, value,
                                 sizeof(*value)) == 0;
}

static bool futex_write_user_word(int *uaddr, int value) {
    if (!uaddr)
        return false;

    return write_task_user_memory(current_task, (uint64_t)uaddr, &value,
                                  sizeof(value)) == 0;
}

static void futex_enqueue_locked(futex_bucket_t *bucket,
                                 struct futex_wait *wait, uint32_t bucket_id) {
    if (!bucket || !wait)
        return;

    wait->next = NULL;
    wait->bucket_id = bucket_id;

    if (bucket->tail)
        bucket->tail->next = wait;
    else
        bucket->head = wait;

    bucket->tail = wait;
}

static bool futex_dequeue_from_bucket_locked(futex_bucket_t *bucket,
                                             struct futex_wait *target) {
    struct futex_wait *prev = NULL;
    struct futex_wait *curr;

    if (!bucket || !target)
        return false;

    curr = bucket->head;

    while (curr) {
        if (curr == target) {
            if (prev)
                prev->next = curr->next;
            else
                bucket->head = curr->next;

            if (bucket->tail == curr)
                bucket->tail = prev;

            curr->next = NULL;
            return true;
        }
        prev = curr;
        curr = curr->next;
    }

    return false;
}

static bool futex_dequeue_locked(struct futex_wait *target) {
    if (!target)
        return false;

    return futex_dequeue_from_bucket_locked(
        futex_bucket_for_id(target->bucket_id), target);
}

static int futex_wake_locked(futex_bucket_t *bucket, const futex_key_t *key,
                             int val, uint32_t bitset) {
    if (val <= 0)
        return 0;

    struct futex_wait *prev = NULL;
    struct futex_wait *curr = bucket ? bucket->head : NULL;
    int woke = 0;

    while (curr) {
        struct futex_wait *next = curr->next;

        if (!curr->task || curr->task->state == TASK_DIED) {
            if (prev)
                prev->next = next;
            else
                bucket->head = next;

            if (bucket->tail == curr)
                bucket->tail = prev;

            curr->next = NULL;
            curr = next;
            continue;
        }

        if (futex_key_equal(curr, key) && (curr->bitset & bitset) != 0 &&
            woke < val) {
            if (prev)
                prev->next = next;
            else
                bucket->head = next;

            if (bucket->tail == curr)
                bucket->tail = prev;

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

    return boot_get_boottime() * 1000000000 + nano_time();
}

static inline bool futex_should_interrupt_before_sleep(void) {
    return task_signal_has_deliverable(current_task);
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
        .bucket_id = 0,
        .bitset = bitset,
    };
    uint32_t bucket_id;
    futex_bucket_t *bucket = futex_bucket_for_key(key, &bucket_id);

    spin_lock(&bucket->lock);
    int uval;
    if (!futex_read_user_word(uaddr, &uval)) {
        spin_unlock(&bucket->lock);
        return (uint64_t)-EFAULT;
    }
    if (uval != val) {
        spin_unlock(&bucket->lock);
        return (uint64_t)-EAGAIN;
    }
    if (timeout && tmo == 0) {
        spin_unlock(&bucket->lock);
        return (uint64_t)-ETIMEDOUT;
    }
    if (futex_should_interrupt_before_sleep()) {
        spin_unlock(&bucket->lock);
        return (uint64_t)-EINTR;
    }
    futex_enqueue_locked(bucket, &wait, bucket_id);
    spin_unlock(&bucket->lock);

    int reason = task_block(current_task, TASK_BLOCKING, tmo, "futex_wait");

    spin_lock(&bucket->lock);
    futex_dequeue_locked(&wait);
    spin_unlock(&bucket->lock);

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

    futex_bucket_t *bucket = futex_bucket_for_key(key, NULL);

    spin_lock(&bucket->lock);
    int count = futex_wake_locked(bucket, key, val, bitset);
    spin_unlock(&bucket->lock);
    return count;
}

uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset) {
    if (bitset == 0)
        return (uint64_t)-EINVAL;

    if (!current_task || !current_task->arch_context || !current_task->mm)
        return 0;

    futex_key_t key = {
        .addr = addr,
        .ctx = (uintptr_t)current_task->mm,
    };
    return sys_futex_wake_key(&key, val, bitset);
}

uint64_t sys_futex(int *uaddr, int op, int val, const struct timespec *timeout,
                   int *uaddr2, int val3) {
    if (!uaddr || check_user_overflow((uint64_t)uaddr, sizeof(int)))
        return (uint64_t)-EFAULT;

    bool is_private = (op & FUTEX_PRIVATE_FLAG) != 0;

    switch (op & FUTEX_CMD_MASK) {
    case FUTEX_WAIT: {
        if (!futex_prefault_user_word(uaddr, false))
            return (uint64_t)-EFAULT;
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wait(uaddr, &key, val, timeout, 0xFFFFFFFF, false,
                              false);
    }
    case FUTEX_WAKE: {
        if (!futex_prefault_user_word(uaddr, false))
            return (uint64_t)-EFAULT;
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wake_key(&key, val, 0xFFFFFFFF);
    }
    case FUTEX_WAIT_BITSET: {
        if (!futex_prefault_user_word(uaddr, false))
            return (uint64_t)-EFAULT;
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;
        return sys_futex_wait(uaddr, &key, val, timeout, (uint32_t)val3, true,
                              (op & FUTEX_CLOCK_REALTIME) != 0);
    }
    case FUTEX_WAKE_BITSET: {
        if (!futex_prefault_user_word(uaddr, false))
            return (uint64_t)-EFAULT;
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

        if (!uaddr2 || check_user_overflow((uint64_t)uaddr2, sizeof(int)))
            return (uint64_t)-EFAULT;
        if (!futex_prefault_user_word(uaddr, false) ||
            !futex_prefault_user_word(uaddr2, true))
            return (uint64_t)-EFAULT;

        futex_key_t key1;
        futex_key_t key2;
        uint64_t ret = futex_build_key(uaddr, is_private, &key1);
        if ((int64_t)ret < 0)
            return ret;
        ret = futex_build_key(uaddr2, is_private, &key2);
        if ((int64_t)ret < 0)
            return ret;
        uint32_t bucket1_id;
        uint32_t bucket2_id;
        futex_bucket_t *bucket1 = futex_bucket_for_key(&key1, &bucket1_id);
        futex_bucket_t *bucket2 = futex_bucket_for_key(&key2, &bucket2_id);

        if (bucket1_id == bucket2_id) {
            spin_lock(&bucket1->lock);
        } else if (bucket1_id < bucket2_id) {
            spin_lock(&bucket1->lock);
            spin_lock(&bucket2->lock);
        } else {
            spin_lock(&bucket2->lock);
            spin_lock(&bucket1->lock);
        }

        int oldval = 0;
        if (!futex_read_user_word(uaddr2, &oldval)) {
            if (bucket1_id != bucket2_id)
                spin_unlock(&bucket2->lock);
            spin_unlock(&bucket1->lock);
            return (uint64_t)-EFAULT;
        }
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
            if (bucket1_id != bucket2_id)
                spin_unlock(&bucket2->lock);
            spin_unlock(&bucket1->lock);
            return (uint64_t)-ENOSYS;
        }

        if (!futex_write_user_word(uaddr2, newval)) {
            if (bucket1_id != bucket2_id)
                spin_unlock(&bucket2->lock);
            spin_unlock(&bucket1->lock);
            return (uint64_t)-EFAULT;
        }

        int ret_count = futex_wake_locked(bucket1, &key1, val, 0xFFFFFFFF);

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
            ret_count += futex_wake_locked(bucket2, &key2, val2, 0xFFFFFFFF);
        }

        if (bucket1_id != bucket2_id)
            spin_unlock(&bucket2->lock);
        spin_unlock(&bucket1->lock);
        return ret_count;
    }
    case FUTEX_LOCK_PI: {
        if (!futex_prefault_user_word(uaddr, true))
            return (uint64_t)-EFAULT;
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
            .bucket_id = 0,
            .bitset = (uint32_t)val3 ? (uint32_t)val3 : 0xFFFFFFFF,
        };
        uint32_t bucket_id;
        futex_bucket_t *bucket = futex_bucket_for_key(&key, &bucket_id);

    retry:
        spin_lock(&bucket->lock);
        int owner = 0;
        if (!futex_read_user_word(uaddr, &owner)) {
            spin_unlock(&bucket->lock);
            return (uint64_t)-EFAULT;
        }

        if ((owner & INT32_MAX) == 0) {
            if (!futex_write_user_word(uaddr, (int)current_task->pid)) {
                spin_unlock(&bucket->lock);
                return (uint64_t)-EFAULT;
            }
            spin_unlock(&bucket->lock);
            return 0;
        } else {
            if (timeout && tmo == 0) {
                spin_unlock(&bucket->lock);
                return (uint64_t)-ETIMEDOUT;
            }
            if (futex_should_interrupt_before_sleep()) {
                spin_unlock(&bucket->lock);
                return (uint64_t)-EINTR;
            }
            futex_enqueue_locked(bucket, &wait, bucket_id);
            spin_unlock(&bucket->lock);

            int reason =
                task_block(current_task, TASK_BLOCKING, tmo, "futex_lock_pi");

            spin_lock(&bucket->lock);
            futex_dequeue_locked(&wait);
            spin_unlock(&bucket->lock);

            if (reason == ETIMEDOUT)
                return (uint64_t)-ETIMEDOUT;
            if (reason != EOK)
                return (uint64_t)-EINTR;

            goto retry;
        }
    }
    case FUTEX_UNLOCK_PI: {
        if (!futex_prefault_user_word(uaddr, true))
            return (uint64_t)-EFAULT;
        futex_key_t key;
        uint64_t ret = futex_build_key(uaddr, is_private, &key);
        if ((int64_t)ret < 0)
            return ret;

        futex_bucket_t *bucket = futex_bucket_for_key(&key, NULL);

        spin_lock(&bucket->lock);
        int owner = 0;
        if (!futex_read_user_word(uaddr, &owner)) {
            spin_unlock(&bucket->lock);
            return (uint64_t)-EFAULT;
        }
        if ((owner & INT32_MAX) != (int)current_task->pid) {
            spin_unlock(&bucket->lock);
            return (uint64_t)-EPERM;
        }
        if (!futex_write_user_word(uaddr, 0)) {
            spin_unlock(&bucket->lock);
            return (uint64_t)-EFAULT;
        }
        futex_wake_locked(bucket, &key, 1, 0xFFFFFFFF);
        spin_unlock(&bucket->lock);
        return 0;
    }
    case FUTEX_REQUEUE:
    case FUTEX_CMP_REQUEUE: {
        if (!uaddr2 || check_user_overflow((uint64_t)uaddr2, sizeof(int)))
            return (uint64_t)-EFAULT;
        if (!futex_prefault_user_word(uaddr, false) ||
            !futex_prefault_user_word(uaddr2, false))
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
        uint32_t src_bucket_id;
        uint32_t dst_bucket_id;
        futex_bucket_t *src_bucket =
            futex_bucket_for_key(&src_key, &src_bucket_id);
        futex_bucket_t *dst_bucket =
            futex_bucket_for_key(&dst_key, &dst_bucket_id);

        if (src_bucket_id == dst_bucket_id) {
            spin_lock(&src_bucket->lock);
        } else if (src_bucket_id < dst_bucket_id) {
            spin_lock(&src_bucket->lock);
            spin_lock(&dst_bucket->lock);
        } else {
            spin_lock(&dst_bucket->lock);
            spin_lock(&src_bucket->lock);
        }

        int uval3;
        if (!futex_read_user_word(uaddr, &uval3)) {
            if (src_bucket_id != dst_bucket_id)
                spin_unlock(&dst_bucket->lock);
            spin_unlock(&src_bucket->lock);
            return (uint64_t)-EFAULT;
        }
        if ((op & FUTEX_CMD_MASK) == FUTEX_CMP_REQUEUE && uval3 != val3) {
            if (src_bucket_id != dst_bucket_id)
                spin_unlock(&dst_bucket->lock);
            spin_unlock(&src_bucket->lock);
            return (uint64_t)-EAGAIN;
        }

        int wake_count =
            futex_wake_locked(src_bucket, &src_key, val, 0xFFFFFFFF);
        int requeue_count = 0;

        if (nr_requeue > 0) {
            struct futex_wait *prev = NULL;
            struct futex_wait *curr = src_bucket->head;
            while (curr && requeue_count < nr_requeue) {
                struct futex_wait *next = curr->next;
                if (!curr->task || curr->task->state == TASK_DIED) {
                    if (prev)
                        prev->next = next;
                    else
                        src_bucket->head = next;
                    if (src_bucket->tail == curr)
                        src_bucket->tail = prev;
                    curr->next = NULL;
                    curr = next;
                    continue;
                }
                if (futex_key_equal(curr, &src_key)) {
                    if (src_bucket_id != dst_bucket_id) {
                        if (prev)
                            prev->next = next;
                        else
                            src_bucket->head = next;
                        if (src_bucket->tail == curr)
                            src_bucket->tail = prev;
                        curr->next = NULL;
                        curr->key_addr = dst_key.addr;
                        curr->key_ctx = dst_key.ctx;
                        futex_enqueue_locked(dst_bucket, curr, dst_bucket_id);
                        curr = next;
                    } else {
                        curr->key_addr = dst_key.addr;
                        curr->key_ctx = dst_key.ctx;
                        prev = curr;
                        curr = next;
                    }
                    requeue_count++;
                    continue;
                }
                prev = curr;
                curr = next;
            }
        }

        if (src_bucket_id != dst_bucket_id)
            spin_unlock(&dst_bucket->lock);
        spin_unlock(&src_bucket->lock);
        return wake_count + requeue_count;
    }
    default:
        printk("futex: Unsupported op: %d\n", op);
        return (uint64_t)-ENOSYS;
    }
}

void futex_init() {
    for (uint32_t bucket_id = 0; bucket_id < FUTEX_BUCKET_COUNT; bucket_id++) {
        spin_init(&futex_buckets[bucket_id].lock);
        futex_buckets[bucket_id].head = NULL;
        futex_buckets[bucket_id].tail = NULL;
    }
}
