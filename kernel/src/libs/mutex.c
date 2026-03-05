#include <libs/mutex.h>
#include <task/task.h>

#define MUTEX_WAIT_SLICE_NS 10000000LL

static void wait_queue_remove_locked(mutex_t *mtx, wait_node_t *target) {
    if (!mtx || !target || !target->queued)
        return;

    wait_node_t *prev = NULL;
    wait_node_t *curr = mtx->wait_head;
    while (curr) {
        if (curr == target) {
            if (prev) {
                prev->next = curr->next;
            } else {
                mtx->wait_head = curr->next;
            }
            if (mtx->wait_tail == curr) {
                mtx->wait_tail = prev;
            }
            curr->next = NULL;
            curr->queued = false;
            return;
        }
        prev = curr;
        curr = curr->next;
    }

    target->next = NULL;
    target->queued = false;
}

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

    for (;;) {
        spin_lock(&mtx->guard);

        if (mtx->locked && mtx->owner == self) {
            mtx->recursion++;

            if (node) {
                wait_queue_remove_locked(mtx, node);
                free(node);
            }
            spin_unlock(&mtx->guard);
            return;
        }

        if (!mtx->locked) {
            mtx->locked = true;
            mtx->owner = self;
            mtx->recursion = 1;

            if (node) {
                wait_queue_remove_locked(mtx, node);
                free(node);
            }
            spin_unlock(&mtx->guard);
            return;
        }

        if (!node) {
            node = malloc(sizeof(wait_node_t));
            if (node) {
                node->task = self;
                node->next = NULL;
                node->queued = false;
            }
        }
        if (node && !node->queued) {
            wait_queue_enqueue(mtx, node);
        }

        spin_unlock(&mtx->guard);

        if (!node) {
            schedule(SCHED_FLAG_YIELD);
            continue;
        }

        int reason =
            task_block(self, TASK_BLOCKING, MUTEX_WAIT_SLICE_NS, "mutex");
        if (reason != EOK && reason != ETIMEDOUT) {
            schedule(SCHED_FLAG_YIELD);
        }
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
