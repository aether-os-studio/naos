#include <task/futex.h>
#include <fs/fs_syscall.h>

spinlock_t futex_lock = {0};
struct futex_wait futex_wait_list = {NULL, NULL, NULL, 0};

uint64_t sys_futex_wait(uint64_t addr, const struct timespec *timeout,
                        uint32_t bitset) {
    spin_lock(&futex_lock);

    struct futex_wait *wait = malloc(sizeof(struct futex_wait));
    wait->uaddr = (void *)addr;
    wait->task = current_task;
    wait->next = NULL;
    wait->bitset = bitset;
    struct futex_wait *curr = &futex_wait_list;
    while (curr && curr->next)
        curr = curr->next;

    curr->next = wait;

    spin_unlock(&futex_lock);

    int tmo = -1;
    if (timeout) {
        tmo = timeout->tv_sec * 1000000000 + timeout->tv_nsec;
    }
    task_block(current_task, TASK_BLOCKING, tmo);

    return 0;
}

uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset) {
    spin_lock(&futex_lock);

    struct futex_wait *curr = &futex_wait_list;
    struct futex_wait *prev = NULL;
    int count = 0;
    while (curr) {
        bool found = false;

        if (curr->uaddr && curr->uaddr == (void *)addr &&
            (curr->bitset & bitset) && ++count <= val) {
            if (!curr->task)
                continue;
            if (curr->task->state == TASK_DIED) {
                if (prev) {
                    prev->next = curr->next;
                }
                free(curr);
                found = true;
                continue;
            }
            task_unblock(curr->task, EOK);
            if (prev) {
                prev->next = curr->next;
            }
            free(curr);
            found = true;
        }
        if (found) {
            curr = prev->next;
        } else {
            prev = curr;
            curr = curr->next;
        }
    }

    spin_unlock(&futex_lock);
    return count;
}

uint64_t sys_futex(int *uaddr, int op, int val, const struct timespec *timeout,
                   int *uaddr2, int val3) {
    if (check_user_overflow((uint64_t)uaddr, sizeof(int)))
        return (uint64_t)-EFAULT;
    if (check_user_overflow((uint64_t)uaddr2, sizeof(int)))
        return (uint64_t)-EFAULT;
    if (check_user_overflow((uint64_t)timeout, sizeof(struct timespec)))
        return (uint64_t)-EFAULT;

    switch (op) {
    case FUTEX_WAIT_PRIVATE:
    case FUTEX_WAIT: {
        int current = *(int *)uaddr;
        if (current != val) {
            return -EAGAIN;
        }

        return sys_futex_wait(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr),
            timeout, 0xFFFFFFFF);
    }
    case FUTEX_WAKE_PRIVATE:
    case FUTEX_WAKE: {
        return sys_futex_wake(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr), val,
            0xFFFFFFFF);
    }
    case FUTEX_WAIT_BITSET_PRIVATE:
    case FUTEX_WAIT_BITSET: {
        int current = *(int *)uaddr;
        if (current != val) {
            return -EAGAIN;
        }

        return sys_futex_wait(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr),
            timeout, val3);
    }
    case FUTEX_WAKE_BITSET_PRIVATE:
    case FUTEX_WAKE_BITSET: {
        return sys_futex_wake(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr), val,
            val3);
    }
    case FUTEX_LOCK_PI:
    case FUTEX_LOCK_PI_PRIVATE: {
    retry:
        if ((*uaddr & INT32_MAX) == 0) {
            *uaddr = current_task->pid;
            return 0;
        } else {
            struct futex_wait *wait = malloc(sizeof(struct futex_wait));
            wait->uaddr = uaddr;
            wait->task = current_task;
            wait->next = NULL;
            wait->bitset = (uint32_t)val3;
            struct futex_wait *curr = &futex_wait_list;
            while (curr && curr->next)
                curr = curr->next;

            curr->next = wait;

            spin_unlock(&futex_lock);

            int tmo = -1;
            if (timeout)
                tmo = timeout->tv_sec * 1000000000 + timeout->tv_nsec;
            task_block(current_task, TASK_BLOCKING, tmo);

            goto retry;
        }
    }
    case FUTEX_UNLOCK_PI:
    case FUTEX_UNLOCK_PI_PRIVATE: {
        if ((*uaddr & INT32_MAX) != current_task->pid) {
            return -EPERM;
        }
        *uaddr = 0;

        struct futex_wait *curr = &futex_wait_list;
        struct futex_wait *prev = NULL;
        int count = 0;
        while (curr) {
            bool found = false;

            if (curr->uaddr && curr->uaddr == uaddr && ++count <= 1) {
                task_unblock(curr->task, EOK);
                if (prev) {
                    prev->next = curr->next;
                }
                free(curr);
                found = true;
            }
            if (found) {
                curr = prev->next;
            } else {
                prev = curr;
                curr = curr->next;
            }
        }

        return 0;
    }
    // case FUTEX_REQUEUE_PRIVATE:
    // case FUTEX_REQUEUE: {
    //     spin_lock(&futex_lock);

    //     struct futex_wait *curr = &futex_wait_list;
    //     struct futex_wait *prev = NULL;
    //     int wake_count = 0;
    //     int requeue_count = 0;

    //     // 遍历等待队列
    //     while (curr) {
    //         bool found = false;

    //         // 检查是否匹配原始地址
    //         if (curr->uaddr && curr->uaddr == (void *)translate_address(
    //                                               get_current_page_dir(true),
    //                                               (uint64_t)uaddr)) {
    //             // 先唤醒val个线程
    //             if (wake_count < val) {
    //                 task_unblock(curr->task, EOK);
    //                 if (prev) {
    //                     prev->next = curr->next;
    //                 }
    //                 struct futex_wait *to_free = curr;
    //                 curr = curr->next;
    //                 free(to_free);
    //                 wake_count++;
    //                 found = true;
    //             }
    //             // 然后转移val3个线程到新地址
    //             else if (requeue_count < val3) {
    //                 // 修改等待地址为目标地址
    //                 curr->uaddr = (void *)translate_address(
    //                     get_current_page_dir(true), (uint64_t)uaddr2);
    //                 requeue_count++;
    //                 prev = curr;
    //                 curr = curr->next;
    //             } else {
    //                 // 已经处理完所有需要的线程
    //                 break;
    //             }
    //         }

    //         if (!found) {
    //             prev = curr;
    //             curr = curr->next;
    //         }
    //     }

    //     spin_unlock(&futex_lock);
    //     return wake_count + requeue_count;
    // }
    default:
        printk("futex: Unsupported op: %d\n", op);
        return -ENOSYS;
    }
}
