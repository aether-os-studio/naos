#include "task/rrs.h"

void add_rrs_entity(task_t *task, rrs_t *scheduler) {
    spin_lock(&scheduler->queue_lock);
    struct sched_entity *entity = task->sched_info;
    if (!entity->on_rq) {
        entity->task = task;
        entity->node = list_enqueue(scheduler->sched_queue, entity);
        entity->on_rq = true;
    }
    spin_unlock(&scheduler->queue_lock);
}

void remove_rrs_entity(task_t *thread, rrs_t *scheduler) {
    spin_lock(&scheduler->queue_lock);
    struct sched_entity *entity = thread->sched_info;
    if (entity->on_rq) {
        if (entity == scheduler->curr) {
            list_node_t *nextL = entity->node->next;

            if (nextL == NULL) {
                nextL = scheduler->sched_queue->head;
            }

            if (nextL == entity->node || scheduler->sched_queue->size == 1) {
                scheduler->curr = scheduler->idle;
            } else {
                scheduler->curr = nextL->data;
            }
        }

        list_remove_node(scheduler->sched_queue, entity->node);
        entity->on_rq = false;
    }
    spin_unlock(&scheduler->queue_lock);
}

task_t *rrs_pick_next_task(rrs_t *scheduler) {
    struct sched_entity *entity = scheduler->curr;
    list_node_t *nextL = NULL;

    if (!entity || entity == scheduler->idle || !entity->on_rq) {
        nextL = scheduler->sched_queue->head;
    } else {
        nextL = entity->node->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    }

    if (nextL == NULL || scheduler->sched_queue->size == 0) {
        scheduler->curr = scheduler->idle;
        return scheduler->idle->task;
    }

    list_node_t *start = nextL;

    do {
        struct sched_entity *next = nextL->data;

        if (next && next->task && next->task->state == TASK_READY) {
            scheduler->curr = next;
            return next->task;
        }

        nextL = nextL->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    } while (nextL != start && nextL != NULL);

    scheduler->curr = scheduler->idle;
    return scheduler->idle->task;
}
