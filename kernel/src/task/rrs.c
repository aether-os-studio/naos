#include "task/rrs.h"

void add_rrs_entity(task_t *task, rrs_t *scheduler) {
    struct sched_entity *entity = task->sched_info;
    if (!entity->on_rq) {
        entity->task = task;
        entity->node = list_enqueue(scheduler->sched_queue, entity);
        entity->on_rq = true;
    }
}

void remove_rrs_entity(task_t *thread, rrs_t *scheduler) {
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
}

task_t *rrs_pick_next_task(rrs_t *scheduler) {
    struct sched_entity *entity = scheduler->curr;
    list_node_t *nextL = NULL;

    if (!entity || entity == scheduler->idle) {
        nextL = scheduler->sched_queue->head;
    } else if (entity->on_rq) {
        nextL = entity->node->next;
        if (nextL == NULL) {
            nextL = scheduler->sched_queue->head;
        }
    } else {
        nextL = scheduler->sched_queue->head;
    }

    if (nextL == NULL) {
        scheduler->curr = scheduler->idle;
        return scheduler->idle->task;
    }

    struct sched_entity *next = nextL->data;
    scheduler->curr = next;
    return next->task;
}
