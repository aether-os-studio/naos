#pragma once

#include <libs/klibc.h>
#include <libs/llist_queue.h>
#include <task/task.h>

struct sched_entity {
    task_t *task;
    list_node_t *node;
    bool on_rq;
};

typedef struct sched_rq {
    list_queue_t *sched_queue;
    struct sched_entity *idle;
    struct sched_entity *curr;
    spinlock_t lock;
} sched_rq_t;

void add_sched_entity(task_t *task, sched_rq_t *scheduler);
void remove_sched_entity(task_t *task, sched_rq_t *scheduler);
task_t *sched_pick_next_task(sched_rq_t *scheduler);
task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded);
