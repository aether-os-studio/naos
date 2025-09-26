#include <task/futex.h>
#include <fs/fs_syscall.h>

spinlock_t futex_lock = {0};
struct futex_wait futex_wait_list = {NULL, NULL, NULL, 0};

uint64_t sys_futex_wait(uint64_t addr, const struct timespec *timeout) {
    struct futex_wait *wait = malloc(sizeof(struct futex_wait));
    wait->uaddr = (void *)addr;
    wait->task = current_task;
    wait->next = NULL;
    wait->bitset = 0xFFFFFFFF;
    struct futex_wait *curr = &futex_wait_list;
    while (curr && curr->next)
        curr = curr->next;

    curr->next = wait;

    spin_unlock(&futex_lock);

    int tmo = -1;
    if (timeout) {
        tmo = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
    }
    task_block(current_task, TASK_BLOCKING, tmo);

    return 0;
}

uint64_t sys_futex_wake(uint64_t addr, int val) {
    spin_lock(&futex_lock);

    struct futex_wait *curr = &futex_wait_list;
    struct futex_wait *prev = NULL;
    int count = 0;
    while (curr) {
        bool found = false;

        if (curr->uaddr && curr->uaddr == (void *)addr && ++count <= val) {
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
    switch (op) {
    case FUTEX_WAIT: {

        spin_lock(&futex_lock);

        int current = *(int *)uaddr;
        if (current != val) {
            spin_unlock(&futex_lock);
            return -EWOULDBLOCK;
        }

        return sys_futex_wait(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr),
            timeout);
    }
    case FUTEX_WAIT_PRIVATE: {
        spin_lock(&futex_lock);

        int current = *(int *)uaddr;
        if (current != val) {
            spin_unlock(&futex_lock);
            return -EWOULDBLOCK;
        }

        return sys_futex_wait((uint64_t)uaddr, timeout);
    }
    case FUTEX_WAKE: {
        return sys_futex_wake(
            translate_address(get_current_page_dir(true), (uint64_t)uaddr),
            val);
    }
    case FUTEX_WAKE_PRIVATE: {
        return sys_futex_wake((uint64_t)uaddr, val);
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
                tmo = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
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
    default:
        printk("futex: Unsupported op: %d\n", op);
        return -ENOSYS;
    }
}
