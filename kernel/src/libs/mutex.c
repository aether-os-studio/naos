#include <libs/mutex.h>
#include <task/task.h>

void mutex_init(mutex_t *mtx) {
    spin_init(&mtx->guard);
    mtx->locked = false;
    mtx->owner = NULL;
    mtx->recursion = 0;
    mtx->wait_head = NULL;
    mtx->wait_tail = NULL;
}

void mutex_lock(mutex_t *mtx) {
    task_t *self = current_task;
    wait_node_t *node = NULL;

    bool state = arch_interrupt_enabled();

    arch_disable_interrupt();

    for (;;) {
        spin_lock(&mtx->guard);

        if (mtx->locked && mtx->owner == self) {
            mtx->recursion++;

            spin_unlock(&mtx->guard);
            if (node) {
                free(node);
            }
            goto ret;
        }

        if (!mtx->locked) {
            mtx->locked = true;
            mtx->owner = self;
            mtx->recursion = 1;
            self->preempt++;

            spin_unlock(&mtx->guard);
            if (node) {
                free(node);
            }
            goto ret;
        }

        if (!node) {
            node = malloc(sizeof(wait_node_t));
            if (node) {
                node->task = self;
                wait_queue_enqueue(mtx, node);
            }
        }

        spin_unlock(&mtx->guard);

        if (!node) {
            schedule(SCHED_FLAG_YIELD);
            continue;
        }

        task_block(self, TASK_BLOCKING, -1, "mutex");
    }

ret:
    if (state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }
}

bool mutex_trylock(mutex_t *mtx) {
    task_t *self = current_task;
    bool locked = false;

    spin_lock(&mtx->guard);

    if (mtx->locked && mtx->owner == self) {
        mtx->recursion++;
        locked = true;
        goto out;
    }

    if (!mtx->locked) {
        mtx->locked = true;
        mtx->owner = self;
        mtx->recursion = 1;
        self->preempt++;
        locked = true;
        goto out;
    }

out:
    spin_unlock(&mtx->guard);
    return locked;
}

void mutex_unlock(mutex_t *mtx) {
    task_t *self = current_task;
    wait_node_t *node = NULL;
    task_t *waiter = NULL;

    spin_lock(&mtx->guard);

    if (mtx->owner != self) {
        spin_unlock(&mtx->guard);
        return;
    }

    if (mtx->recursion > 1) {
        mtx->recursion--;
        spin_unlock(&mtx->guard);
        return;
    }

    mtx->locked = false;
    mtx->owner = NULL;
    mtx->recursion = 0;

    if (self->preempt > 0) {
        self->preempt--;
    }

    while ((node = wait_queue_dequeue(mtx))) {
        waiter = node->task;
        if (!waiter || waiter->state == TASK_DIED) {
            free(node);
            waiter = NULL;
            continue;
        }

        break;
    }

    spin_unlock(&mtx->guard);

    if (waiter) {
        task_unblock(waiter, EOK);
    }
}
