#include "task/sched.h"

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    spin_lock(&scheduler->sched_queue->lock);
    struct sched_entity *entity = scheduler->curr;
    list_node_t *nextL = NULL;

    if (!entity || entity == scheduler->idle || !entity->on_rq ||
        entity->node == NULL) {
        nextL = scheduler->sched_queue->head;
    } else {
        nextL = entity->node->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    }

    if (nextL == NULL || scheduler->sched_queue->size == 0) {
        scheduler->curr = scheduler->idle;
        spin_unlock(&scheduler->sched_queue->lock);
        return scheduler->idle->task;
    }

    list_node_t *start = nextL;
    do {
        struct sched_entity *next = nextL->data;

        if (next && next->on_rq && next->task &&
            next->task->state == TASK_READY && next->task != excluded) {
            scheduler->curr = next;
            spin_unlock(&scheduler->sched_queue->lock);
            return next->task;
        }

        nextL = nextL->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    } while (nextL != start && nextL != NULL);

    scheduler->curr = scheduler->idle;
    spin_unlock(&scheduler->sched_queue->lock);
    return scheduler->idle->task;
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    struct sched_entity *entity = task->sched_info;
    if (!entity->on_rq) {
        entity->task = task;
        entity->node = list_enqueue(scheduler->sched_queue, entity);
        entity->on_rq = (entity->node != NULL);
    }
}

void remove_sched_entity(task_t *thread, sched_rq_t *scheduler) {
    struct sched_entity *entity = thread->sched_info;
    if (entity->on_rq) {
        entity->on_rq = false;

        spin_lock(&scheduler->sched_queue->lock);

        if (entity == scheduler->curr && entity->node != NULL) {
            list_node_t *nextL = entity->node->next;

            if (nextL == NULL) {
                nextL = scheduler->sched_queue->head;
            }

            if (nextL == entity->node || scheduler->sched_queue->size == 1) {
                scheduler->curr = scheduler->idle;
            } else {
                scheduler->curr = nextL->data;
            }
        } else if (entity == scheduler->curr) {
            scheduler->curr = scheduler->idle;
        }

        spin_unlock(&scheduler->sched_queue->lock);

        list_remove_node(scheduler->sched_queue, entity->node);
        entity->node = NULL;
    }
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    return sched_pick_next_task_internal(scheduler, NULL);
}

task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded) {
    return sched_pick_next_task_internal(scheduler, excluded);
}
