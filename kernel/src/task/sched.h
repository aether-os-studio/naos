#pragma once

#include <libs/klibc.h>
#include <libs/llist_queue.h>
#include <libs/rbtree.h>
#include <task/task.h>

struct sched_entity {
    task_t *task;
    list_node_t *node;
    bool on_rq;
    bool queued;
    bool started;
    uint64_t vruntime;
    uint64_t deadline;
    uint64_t exec_start_ns;
    uint32_t weight;
    rb_node_t run_node;
    uint64_t subtree_min_vruntime;
};

typedef struct sched_rq {
    list_queue_t *sched_queue;
    struct sched_entity *idle;
    struct sched_entity *curr;
    rb_root_t run_tree;
    uint64_t min_vruntime;
    uint64_t total_weight;
    spinlock_t lock;
} sched_rq_t;

void add_sched_entity(task_t *task, sched_rq_t *scheduler);
void remove_sched_entity(task_t *task, sched_rq_t *scheduler);
task_t *sched_pick_next_task(sched_rq_t *scheduler);
task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler, task_t *excluded);
