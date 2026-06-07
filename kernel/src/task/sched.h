#pragma once

#include <libs/klibc.h>
#include <libs/rbtree.h>
#include <task/task.h>

struct sched_rq;

struct sched_entity {
    task_t *task;
    rb_node_t run_node;
    struct sched_rq *rq;
    uint64_t vruntime;
    uint64_t deadline;
    uint64_t slice_ns;
    uint64_t exec_start_ns;
    bool on_rq;
};

typedef struct sched_rq {
    rb_root_t run_tree;
    struct sched_entity *idle;
    struct sched_entity *curr;
    uint64_t min_vruntime;
    uint64_t load_weight;
    size_t nr_running;
    size_t nr_queued;
    spinlock_t lock;
} sched_rq_t;

void add_sched_entity(task_t *task, sched_rq_t *scheduler);
void add_sched_entity_wakeup(task_t *task, sched_rq_t *scheduler);
void remove_sched_entity(task_t *task, sched_rq_t *scheduler);
void sched_requeue_current(task_t *task, sched_rq_t *scheduler);
void sched_account_runtime(task_t *task, uint64_t delta_ns);
void sched_set_task_nice(task_t *task, int niceval);
bool sched_should_preempt(sched_rq_t *scheduler, task_t *curr_task,
                          uint64_t now_ns);
bool sched_should_preempt_on_wakeup(sched_rq_t *scheduler, task_t *wakeup_task);
bool sched_request_preempt_on_wakeup(sched_rq_t *scheduler,
                                     task_t *wakeup_task);
uint64_t sched_next_preempt_deadline(sched_rq_t *scheduler, task_t *curr_task,
                                     uint64_t now_ns);
task_t *sched_pick_next_task(sched_rq_t *scheduler);
task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler, task_t *excluded);
size_t sched_rq_nr_running(sched_rq_t *scheduler);
size_t sched_rq_nr_queued(sched_rq_t *scheduler);
