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
        list_remove_node(scheduler->sched_queue, entity->node);
        entity->on_rq = false;
        if (entity == scheduler->curr) {
            scheduler->curr = scheduler->idle;
        }
    }
}

task_t *rrs_pick_next_task(rrs_t *scheduler) {
    struct sched_entity *entity = scheduler->curr;
    list_node_t *nextL = entity ? entity->node->next : NULL;
    struct sched_entity *next;
    if (nextL == NULL)
        next = scheduler->idle;
    else
        next = nextL->data;
    scheduler->curr = next;
    return next->task;
}
