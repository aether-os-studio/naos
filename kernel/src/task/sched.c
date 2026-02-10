#include "task/sched.h"

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    struct sched_entity *entity = task->sched_info;
    if (!entity->on_rq) {
        entity->on_rq = true;
        entity->task = task;
        entity->node = list_enqueue(scheduler->sched_queue, entity);
    }
}

void remove_sched_entity(task_t *thread, sched_rq_t *scheduler) {
    struct sched_entity *entity = thread->sched_info;
    if (entity->on_rq) {
        entity->on_rq = false;

        spin_lock(&scheduler->sched_queue->lock);

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

        spin_unlock(&scheduler->sched_queue->lock);

        list_remove_node(scheduler->sched_queue, entity->node);
        entity->node = NULL;
    }
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    spin_lock_no_irqsave(&scheduler->sched_queue->lock);
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
        spin_unlock_no_irqstore(&scheduler->sched_queue->lock);
        return scheduler->idle->task;
    }

    list_node_t *start = nextL;
    do {
        struct sched_entity *next = nextL->data;

        if (next && next->on_rq && next->task &&
            next->task->state == TASK_READY) {
            scheduler->curr = next;
            spin_unlock_no_irqstore(&scheduler->sched_queue->lock);
            return next->task;
        }

        nextL = nextL->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    } while (nextL != start && nextL != NULL);

    scheduler->curr = scheduler->idle;
    spin_unlock_no_irqstore(&scheduler->sched_queue->lock);
    return scheduler->idle->task;
}