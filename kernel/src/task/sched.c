#include "task/sched.h"

#define NICE_0_WEIGHT 1024U

static inline uint64_t sched_calc_delta(uint64_t delta_exec, uint32_t weight) {
    if (weight == 0)
        weight = NICE_0_WEIGHT;
    return (delta_exec * NICE_0_WEIGHT) / weight;
}

static inline uint32_t sched_default_weight(const task_t *task) {
    (void)task;
    return NICE_0_WEIGHT;
}

static void sched_insert_entity(sched_rq_t *rq, struct sched_entity *se) {
    rb_node_t **link = &rq->task_tree.rb_node;
    rb_node_t *parent = NULL;

    while (*link) {
        struct sched_entity *entry =
            rb_entry(*link, struct sched_entity, rb_node);
        parent = *link;

        if (se->vruntime < entry->vruntime) {
            link = &(*link)->rb_left;
        } else if (se->vruntime > entry->vruntime) {
            link = &(*link)->rb_right;
        } else if (se < entry) {
            link = &(*link)->rb_left;
        } else {
            link = &(*link)->rb_right;
        }
    }

    rb_node_t *node = &se->rb_node;
    node->rb_parent_color = (uint64_t)parent;
    node->rb_left = NULL;
    node->rb_right = NULL;
    *link = node;

    rb_insert_color(node, &rq->task_tree);
}

static void sched_update_min_vruntime(sched_rq_t *rq) {
    rb_node_t *left = rb_first(&rq->task_tree);
    if (left) {
        struct sched_entity *se = rb_entry(left, struct sched_entity, rb_node);
        rq->min_vruntime = se->vruntime;
    }
}

static void sched_update_curr(sched_rq_t *rq) {
    struct sched_entity *curr = rq->curr;
    if (!curr || curr == rq->idle || !curr->on_rq)
        return;

    uint64_t now = nano_time();
    if (curr->exec_start == 0) {
        curr->exec_start = now;
        return;
    }

    uint64_t delta_exec = now - curr->exec_start;
    if (delta_exec == 0)
        return;

    curr->sum_exec_runtime += delta_exec;
    curr->vruntime += sched_calc_delta(delta_exec, curr->weight);
    curr->exec_start = now;

    rb_erase(&curr->rb_node, &rq->task_tree);
    sched_insert_entity(rq, curr);
    sched_update_min_vruntime(rq);
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    struct sched_entity *entity = task->sched_info;
    if (entity->on_rq)
        return;

    entity->task = task;
    if (entity->weight == 0)
        entity->weight = sched_default_weight(task);

    entity->rb_node.rb_parent_color = 0;
    entity->rb_node.rb_left = NULL;
    entity->rb_node.rb_right = NULL;

    spin_lock(&scheduler->lock);

    if (entity->vruntime < scheduler->min_vruntime)
        entity->vruntime = scheduler->min_vruntime;

    sched_insert_entity(scheduler, entity);
    entity->on_rq = true;
    scheduler->nr_running++;
    sched_update_min_vruntime(scheduler);

    spin_unlock(&scheduler->lock);
}

void remove_sched_entity(task_t *task, sched_rq_t *scheduler) {
    struct sched_entity *entity = task->sched_info;
    if (!entity->on_rq)
        return;

    spin_lock(&scheduler->lock);

    if (entity == scheduler->curr)
        sched_update_curr(scheduler);

    rb_erase(&entity->rb_node, &scheduler->task_tree);
    entity->on_rq = false;
    entity->exec_start = 0;
    if (scheduler->nr_running > 0)
        scheduler->nr_running--;

    if (scheduler->curr == entity)
        scheduler->curr = scheduler->idle;

    sched_update_min_vruntime(scheduler);
    spin_unlock(&scheduler->lock);
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    spin_lock(&scheduler->lock);

    sched_update_curr(scheduler);

    rb_node_t *left = rb_first(&scheduler->task_tree);
    if (!left || scheduler->nr_running == 0) {
        scheduler->curr = scheduler->idle;
        spin_unlock(&scheduler->lock);
        return scheduler->idle->task;
    }

    struct sched_entity *next = rb_entry(left, struct sched_entity, rb_node);
    scheduler->curr = next;
    next->exec_start = nano_time();

    spin_unlock(&scheduler->lock);
    return next->task;
}
