#pragma once

#include <libs/llist_queue.h>
#include <task/task.h>

struct sched_entity {
    task_t *task;
    list_node_t *node;
    bool on_rq;
};

typedef struct rrs_scheduler {
    list_queue_t *sched_queue;
    struct sched_entity *idle;
    struct sched_entity *curr;
    spinlock_t queue_lock;
} rrs_t;

void add_rrs_entity(task_t *task, rrs_t *scheduler);
void remove_rrs_entity(task_t *thread, rrs_t *scheduler);
task_t *rrs_pick_next_task(rrs_t *scheduler);
