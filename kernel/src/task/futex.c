#include <task/futex.h>
#include <fs/fs_syscall.h>

spinlock_t futex_lock = {0};
struct futex_wait futex_wait_list = {NULL, NULL, NULL};

int sys_futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
    switch (op)
    {
    case FUTEX_WAIT:
    case FUTEX_WAIT_PRIVATE:
    {
        spin_lock(&futex_lock);

        int current = *(int *)uaddr;
        if (current != val)
        {
            spin_unlock(&futex_lock);
            return -EWOULDBLOCK;
        }

        struct futex_wait *wait = malloc(sizeof(struct futex_wait));
        wait->uaddr = uaddr;
        wait->task = current_task;
        wait->next = NULL;
        wait->bitset = 0xFFFFFFFF;
        struct futex_wait *curr = &futex_wait_list;
        while (curr && curr->next)
            curr = curr->next;

        curr->next = wait;

        spin_unlock(&futex_lock);

        int tmo = -1;
        if (timeout)
            tmo = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
        task_block(current_task, TASK_BLOCKING, tmo);

        arch_disable_interrupt();

        return 0;
    }
    case FUTEX_WAKE:
    case FUTEX_WAKE_PRIVATE:
    {
        spin_lock(&futex_lock);

        struct futex_wait *curr = &futex_wait_list;
        struct futex_wait *prev = NULL;
        int count = 0;
        while (curr)
        {
            bool found = false;

            if (curr->uaddr && curr->uaddr == uaddr && ++count <= val)
            {
                task_unblock(curr->task, EOK);
                if (prev)
                {
                    prev->next = curr->next;
                }
                free(curr);
                found = true;
            }
            if (found)
            {
                curr = prev->next;
            }
            else
            {
                prev = curr;
                curr = curr->next;
            }
        }

        spin_unlock(&futex_lock);
        return count;
    }
    case FUTEX_WAIT_BITSET:
    case FUTEX_WAIT_BITSET_PRIVATE:
    {
        spin_lock(&futex_lock);

        int current = *(int *)uaddr;
        if (current != val)
        {
            spin_unlock(&futex_lock);
            return -EWOULDBLOCK;
        }

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

        arch_disable_interrupt();

        return 0;
    }
    case FUTEX_WAKE_BITSET:
    case FUTEX_WAKE_BITSET_PRIVATE:
    {
        spin_lock(&futex_lock);

        struct futex_wait *curr = &futex_wait_list;
        struct futex_wait *prev = NULL;
        int count = 0;
        while (curr)
        {
            bool found = false;

            if (curr->uaddr && curr->uaddr == uaddr && (curr->bitset & val3) && ++count <= val)
            {
                task_unblock(curr->task, EOK);
                if (prev)
                {
                    prev->next = curr->next;
                }
                free(curr);
                found = true;
            }
            if (found)
            {
                curr = prev->next;
            }
            else
            {
                prev = curr;
                curr = curr->next;
            }
        }

        spin_unlock(&futex_lock);
        return count;
    }
    default:
        return -ENOSYS;
    }
}
