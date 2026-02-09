#pragma once

#include <libs/klibc.h>
#include <libs/rbtree.h>
#include <task/task.h>

struct sched_entity {
    task_t *task;
    bool on_rq;
    uint64_t vruntime;
    uint64_t exec_start;
    uint64_t sum_exec_runtime;
    uint32_t weight;
    rb_node_t rb_node;
};

typedef struct sched_rq {
    rb_root_t task_tree;
    spinlock_t lock;
    struct sched_entity *idle;
    struct sched_entity *curr;
    uint64_t min_vruntime;
    uint32_t nr_running;
} sched_rq_t;

typedef sched_rq_t rrs_t;

void add_sched_entity(task_t *task, sched_rq_t *scheduler);
void remove_sched_entity(task_t *task, sched_rq_t *scheduler);
task_t *sched_pick_next_task(sched_rq_t *scheduler);
