#include "task/sched.h"

#define SCHED_NICE_MIN (-20)
#define SCHED_NICE_MAX 19
#define SCHED_NICE_0_WEIGHT 1024U
#define SCHED_BASE_SLICE_NS (1000000000ULL / SCHED_HZ)

static const uint32_t sched_prio_to_weight[] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

static inline uint64_t sched_vruntime_add(uint64_t vruntime, uint64_t delta) {
    if (UINT64_MAX - vruntime < delta)
        return UINT64_MAX;
    return vruntime + delta;
}

static inline bool sched_entity_on_cpu(const struct sched_entity *entity,
                                       const sched_rq_t *scheduler) {
    return entity && scheduler && entity == scheduler->curr &&
           entity != scheduler->idle;
}

static inline bool sched_entity_ready(const struct sched_entity *entity) {
    task_t *task = entity ? entity->task : NULL;

    return entity && task && task->state == TASK_READY;
}

static inline uint32_t sched_weight_from_priority(int priority) {
    if (priority < SCHED_NICE_MIN)
        priority = SCHED_NICE_MIN;
    if (priority > SCHED_NICE_MAX)
        priority = SCHED_NICE_MAX;

    return sched_prio_to_weight[priority - SCHED_NICE_MIN];
}

static inline uint64_t sched_scale_vruntime(uint64_t delta_ns,
                                            uint32_t weight) {
    __uint128_t scaled = (__uint128_t)delta_ns * SCHED_NICE_0_WEIGHT;

    scaled /= weight ? weight : 1;

    if (!scaled && delta_ns)
        return 1;

    return (uint64_t)scaled;
}

static inline uint64_t
sched_entity_slice_vruntime(const struct sched_entity *entity) {
    return sched_scale_vruntime(SCHED_BASE_SLICE_NS,
                                entity ? entity->weight : 1);
}

static inline void sched_entity_refresh_deadline(struct sched_entity *entity) {
    if (!entity)
        return;

    entity->deadline = sched_vruntime_add(entity->vruntime,
                                          sched_entity_slice_vruntime(entity));
}

static inline bool sched_deadline_before(const struct sched_entity *left,
                                         const struct sched_entity *right) {
    if (!right)
        return true;
    if (!left)
        return false;

    if (left->deadline != right->deadline)
        return left->deadline < right->deadline;
    if (left->vruntime != right->vruntime)
        return left->vruntime < right->vruntime;
    if (left->task && right->task && left->task->pid != right->task->pid)
        return left->task->pid < right->task->pid;

    return left < right;
}

static inline bool sched_run_entity_before(const struct sched_entity *left,
                                           const struct sched_entity *right) {
    if (!right)
        return true;
    if (!left)
        return false;

    if (left->vruntime != right->vruntime)
        return left->vruntime < right->vruntime;
    if (left->deadline != right->deadline)
        return left->deadline < right->deadline;
    if (left->task && right->task && left->task->pid != right->task->pid)
        return left->task->pid < right->task->pid;

    return left < right;
}

static inline struct sched_entity *sched_entity_from_run_node(rb_node_t *node) {
    return rb_entry(node, struct sched_entity, run_node);
}

static inline struct sched_entity *sched_subtree_best(const rb_node_t *node) {
    return node ? rb_entry((rb_node_t *)node, struct sched_entity, run_node)
                      ->subtree_best
                : NULL;
}

static inline void sched_entity_reset_run_node(struct sched_entity *entity) {
    if (!entity)
        return;

    entity->queued = false;
    entity->run_node.rb_parent_color = 0;
    entity->run_node.rb_left = NULL;
    entity->run_node.rb_right = NULL;
    entity->subtree_best = entity;
}

static inline void sched_recalc_subtree_best(struct sched_entity *entity) {
    struct sched_entity *best = entity;
    struct sched_entity *left_best =
        sched_subtree_best(entity->run_node.rb_left);
    struct sched_entity *right_best =
        sched_subtree_best(entity->run_node.rb_right);

    if (sched_deadline_before(left_best, best))
        best = left_best;
    if (sched_deadline_before(right_best, best))
        best = right_best;

    entity->subtree_best = best;
}

static inline void sched_update_subtree_best_up(rb_node_t *node) {
    while (node) {
        sched_recalc_subtree_best(sched_entity_from_run_node(node));
        node = rb_parent(node);
    }
}

static inline void sched_tree_insert_locked(sched_rq_t *scheduler,
                                            struct sched_entity *entity) {
    rb_node_t **slot = &scheduler->run_tree.rb_node;
    rb_node_t *parent = NULL;

    while (*slot) {
        struct sched_entity *curr = sched_entity_from_run_node(*slot);
        parent = *slot;

        if (sched_run_entity_before(entity, curr)) {
            slot = &(*slot)->rb_left;
        } else {
            slot = &(*slot)->rb_right;
        }
    }

    sched_entity_reset_run_node(entity);
    rb_set_parent(&entity->run_node, parent);
    rb_set_color(&entity->run_node, KRB_RED);
    *slot = &entity->run_node;

    rb_insert_color(&entity->run_node, &scheduler->run_tree);
    sched_update_subtree_best_up(&entity->run_node);

    entity->queued = true;
    scheduler->total_weight += entity->weight;
    scheduler->weighted_vruntime_sum +=
        (__uint128_t)entity->vruntime * entity->weight;
}

static inline void sched_tree_remove_locked(sched_rq_t *scheduler,
                                            struct sched_entity *entity) {
    rb_node_t *old_parent;
    rb_node_t *successor = NULL;
    rb_node_t *successor_parent = NULL;

    if (!entity || !entity->queued)
        return;

    old_parent = rb_parent(&entity->run_node);

    if (entity->run_node.rb_left && entity->run_node.rb_right) {
        successor = entity->run_node.rb_right;
        while (successor->rb_left)
            successor = successor->rb_left;

        successor_parent = rb_parent(successor);
        if (successor_parent == &entity->run_node)
            successor_parent = NULL;
    }

    scheduler->total_weight -= entity->weight;
    scheduler->weighted_vruntime_sum -=
        (__uint128_t)entity->vruntime * entity->weight;

    rb_erase(&entity->run_node, &scheduler->run_tree);
    sched_entity_reset_run_node(entity);

    if (successor)
        sched_update_subtree_best_up(successor);
    if (successor_parent)
        sched_update_subtree_best_up(successor_parent);
    if (old_parent)
        sched_update_subtree_best_up(old_parent);
    else if (scheduler->run_tree.rb_node)
        sched_update_subtree_best_up(scheduler->run_tree.rb_node);
}

static inline void sched_refresh_min_vruntime_locked(sched_rq_t *scheduler) {
    uint64_t candidate = UINT64_MAX;
    rb_node_t *first;
    struct sched_entity *entity;

    if (!scheduler)
        return;

    first = rb_first(&scheduler->run_tree);
    if (first) {
        entity = sched_entity_from_run_node(first);
        candidate = entity->vruntime;
    }

    entity = scheduler->curr;
    if (sched_entity_on_cpu(entity, scheduler) && entity->on_rq &&
        entity->vruntime < candidate) {
        candidate = entity->vruntime;
    }

    if (candidate != UINT64_MAX && candidate > scheduler->min_vruntime)
        scheduler->min_vruntime = candidate;
}

static inline void sched_place_entity_locked(struct sched_entity *entity,
                                             sched_rq_t *scheduler) {
    uint64_t base_vruntime = scheduler ? scheduler->min_vruntime : 0;

    if (!entity)
        return;

    entity->weight =
        sched_weight_from_priority(entity->task ? entity->task->priority : 0);

    if (!entity->started || entity->vruntime < base_vruntime)
        entity->vruntime = base_vruntime;

    entity->started = true;
    entity->exec_start_ns = 0;
    sched_entity_refresh_deadline(entity);
    sched_entity_reset_run_node(entity);
}

static inline void sched_account_curr_locked(sched_rq_t *scheduler,
                                             uint64_t now_ns,
                                             bool continue_running) {
    struct sched_entity *curr = scheduler ? scheduler->curr : NULL;
    uint64_t delta_ns;
    uint64_t delta_vruntime;

    if (!sched_entity_on_cpu(curr, scheduler) || !curr->on_rq)
        return;

    if (!curr->exec_start_ns) {
        curr->exec_start_ns = continue_running ? now_ns : 0;
        return;
    }

    if (curr->task && now_ns > curr->exec_start_ns) {
        delta_ns = now_ns - curr->exec_start_ns;
        delta_vruntime = sched_scale_vruntime(delta_ns, curr->weight);
        curr->vruntime = sched_vruntime_add(curr->vruntime, delta_vruntime);
        curr->started = true;
        sched_entity_refresh_deadline(curr);
    }

    curr->exec_start_ns = continue_running ? now_ns : 0;
}

static inline void sched_requeue_curr_locked(sched_rq_t *scheduler) {
    struct sched_entity *curr = scheduler ? scheduler->curr : NULL;

    if (!sched_entity_on_cpu(curr, scheduler) || !curr->on_rq || curr->queued ||
        !sched_entity_ready(curr))
        return;

    sched_tree_insert_locked(scheduler, curr);
}

static inline uint64_t sched_avg_vruntime_locked(const sched_rq_t *scheduler) {
    uint64_t avg_vruntime;

    if (!scheduler || !scheduler->total_weight)
        return scheduler ? scheduler->min_vruntime : 0;

    avg_vruntime =
        (uint64_t)(scheduler->weighted_vruntime_sum / scheduler->total_weight);

    return MAX(avg_vruntime, scheduler->min_vruntime);
}

static struct sched_entity *sched_subtree_best_excluding(const rb_node_t *node,
                                                         task_t *excluded) {
    struct sched_entity *entity;
    struct sched_entity *best;
    struct sched_entity *candidate;

    if (!node)
        return NULL;

    entity = rb_entry((rb_node_t *)node, struct sched_entity, run_node);
    if (!excluded || !entity->subtree_best ||
        entity->subtree_best->task != excluded)
        return entity->subtree_best;

    best = entity->task != excluded ? entity : NULL;

    candidate = sched_subtree_best_excluding(node->rb_left, excluded);
    if (sched_deadline_before(candidate, best))
        best = candidate;

    candidate = sched_subtree_best_excluding(node->rb_right, excluded);
    if (sched_deadline_before(candidate, best))
        best = candidate;

    return best;
}

static struct sched_entity *
sched_pick_eligible_entity_locked(sched_rq_t *scheduler, uint64_t avg_vruntime,
                                  task_t *excluded) {
    rb_node_t *node = scheduler ? scheduler->run_tree.rb_node : NULL;
    struct sched_entity *best = NULL;

    while (node) {
        struct sched_entity *entity = sched_entity_from_run_node(node);
        struct sched_entity *left_best;

        if (entity->vruntime <= avg_vruntime) {
            left_best = sched_subtree_best_excluding(node->rb_left, excluded);
            if (sched_deadline_before(left_best, best))
                best = left_best;

            if (entity->task != excluded && sched_deadline_before(entity, best))
                best = entity;

            node = node->rb_right;
        } else {
            node = node->rb_left;
        }
    }

    return best;
}

static struct sched_entity *
sched_pick_min_vruntime_entity_locked(sched_rq_t *scheduler, task_t *excluded) {
    rb_node_t *node = scheduler ? rb_first(&scheduler->run_tree) : NULL;

    while (node) {
        struct sched_entity *entity = sched_entity_from_run_node(node);
        if (entity->task != excluded)
            return entity;
        node = rb_next(node);
    }

    return NULL;
}

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    struct sched_entity *next = NULL;
    task_t *next_task = NULL;
    uint64_t now_ns = nano_time();

    spin_lock(&scheduler->lock);

    sched_account_curr_locked(scheduler, now_ns, false);
    sched_requeue_curr_locked(scheduler);
    sched_refresh_min_vruntime_locked(scheduler);

    while (scheduler->run_tree.rb_node && scheduler->total_weight) {
        next = sched_pick_eligible_entity_locked(
            scheduler, sched_avg_vruntime_locked(scheduler), excluded);
        if (!next)
            next = sched_pick_min_vruntime_entity_locked(scheduler, excluded);

        if (!next)
            break;

        if (sched_entity_ready(next)) {
            sched_tree_remove_locked(scheduler, next);
            scheduler->curr = next;
            next->exec_start_ns = now_ns;
            next_task = next->task;
            goto out;
        }

        sched_tree_remove_locked(scheduler, next);
        next->on_rq = false;
        next->exec_start_ns = 0;
        sched_refresh_min_vruntime_locked(scheduler);
    }

    scheduler->curr = scheduler->idle;
    next_task = scheduler->idle->task;

out:
    spin_unlock(&scheduler->lock);
    return next_task;
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    struct sched_entity *entity;

    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    entity = task->sched_info;
    entity->task = task;

    spin_lock(&scheduler->lock);

    if (entity->on_rq) {
        spin_unlock(&scheduler->lock);
        return;
    }

    sched_account_curr_locked(scheduler, nano_time(), true);
    sched_refresh_min_vruntime_locked(scheduler);
    sched_place_entity_locked(entity, scheduler);

    entity->on_rq = true;
    if (!sched_entity_on_cpu(entity, scheduler) && sched_entity_ready(entity))
        sched_tree_insert_locked(scheduler, entity);

    sched_refresh_min_vruntime_locked(scheduler);
    spin_unlock(&scheduler->lock);
}

void remove_sched_entity(task_t *thread, sched_rq_t *scheduler) {
    struct sched_entity *entity;

    if (__builtin_expect(!thread || !scheduler || !thread->sched_info, 0))
        return;

    entity = thread->sched_info;

    spin_lock(&scheduler->lock);

    if (!entity->on_rq) {
        spin_unlock(&scheduler->lock);
        return;
    }

    if (sched_entity_on_cpu(entity, scheduler))
        sched_account_curr_locked(scheduler, nano_time(), false);

    if (entity->queued)
        sched_tree_remove_locked(scheduler, entity);

    entity->on_rq = false;
    entity->exec_start_ns = 0;

    if (scheduler->curr == entity)
        scheduler->curr = scheduler->idle;

    sched_refresh_min_vruntime_locked(scheduler);
    spin_unlock(&scheduler->lock);
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    return sched_pick_next_task_internal(scheduler, NULL);
}

task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded) {
    return sched_pick_next_task_internal(scheduler, excluded);
}
