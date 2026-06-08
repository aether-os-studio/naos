#include "task/sched.h"
#include <irq/irq_manager.h>

extern sched_rq_t schedulers[MAX_CPU_NUM];

#define SCHED_NICE_MIN (-20)
#define SCHED_NICE_MAX 19
#define SCHED_NICE_0_LOAD 1024ULL
#define SCHED_WAKEUP_GRANULARITY_NS 100000ULL
#define SCHED_WAKEUP_PREEMPT_GRANULARITY_NS 250000ULL
#define SCHED_LATENCY_NS 6000000ULL
#define SCHED_MIN_GRANULARITY_NS 750000ULL
#define SCHED_MAX_GRANULARITY_NS 4000000ULL

static const uint32_t sched_prio_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

static inline int sched_task_nice(task_t *task) {
    int nice = task ? task->nice : 0;

    if (nice < SCHED_NICE_MIN)
        return SCHED_NICE_MIN;
    if (nice > SCHED_NICE_MAX)
        return SCHED_NICE_MAX;
    return nice;
}

static inline uint64_t sched_task_weight(task_t *task) {
    return sched_prio_to_weight[sched_task_nice(task) - SCHED_NICE_MIN];
}

static inline uint64_t sched_nice_weight(int nice) {
    if (nice < SCHED_NICE_MIN)
        nice = SCHED_NICE_MIN;
    if (nice > SCHED_NICE_MAX)
        nice = SCHED_NICE_MAX;
    return sched_prio_to_weight[nice - SCHED_NICE_MIN];
}

static inline uint64_t sched_calc_delta_fair(uint64_t delta_ns, task_t *task) {
    uint64_t weight = sched_task_weight(task);

    if (!delta_ns || weight == SCHED_NICE_0_LOAD)
        return delta_ns;

    return (delta_ns * SCHED_NICE_0_LOAD) / weight;
}

static inline uint64_t sched_entity_slice_locked(sched_rq_t *scheduler,
                                                 struct sched_entity *entity) {
    uint64_t weight = sched_task_weight(entity ? entity->task : NULL);
    uint64_t total_weight = scheduler ? scheduler->load_weight : weight;
    uint64_t slice = SCHED_LATENCY_NS;

    if (scheduler && entity && entity->rq != scheduler)
        total_weight += weight;

    if (total_weight)
        slice = (SCHED_LATENCY_NS * weight) / total_weight;

    if (slice < SCHED_MIN_GRANULARITY_NS)
        return SCHED_MIN_GRANULARITY_NS;
    if (slice > SCHED_MAX_GRANULARITY_NS)
        return SCHED_MAX_GRANULARITY_NS;
    return slice;
}

static inline uint64_t sched_entity_deadline_locked(sched_rq_t *scheduler,
                                                    struct sched_entity *se) {
    uint64_t slice = sched_entity_slice_locked(scheduler, se);

    se->slice_ns = slice;
    return se->vruntime + sched_calc_delta_fair(slice, se->task);
}

static inline bool sched_entity_eligible_locked(sched_rq_t *scheduler,
                                                struct sched_entity *se) {
    return se->vruntime <= scheduler->min_vruntime;
}

static inline void sched_run_node_reset(rb_node_t *node) {
    if (node)
        memset(node, 0, sizeof(*node));
}

static int sched_entity_cmp(struct sched_entity *left,
                            struct sched_entity *right) {
    if (left->deadline < right->deadline)
        return -1;
    if (left->deadline > right->deadline)
        return 1;
    if (left->vruntime < right->vruntime)
        return -1;
    if (left->vruntime > right->vruntime)
        return 1;

    uint64_t left_pid = left->task ? left->task->pid : 0;
    uint64_t right_pid = right->task ? right->task->pid : 0;
    if (left_pid < right_pid)
        return -1;
    if (left_pid > right_pid)
        return 1;

    return left < right ? -1 : (left > right ? 1 : 0);
}

static void sched_update_min_vruntime_locked(sched_rq_t *scheduler) {
    uint64_t min_vruntime = scheduler->min_vruntime;
    bool found = false;

    if (scheduler->curr && scheduler->curr != scheduler->idle &&
        scheduler->curr->task &&
        (scheduler->curr->task->state == TASK_READY ||
         scheduler->curr->task->current_state == TASK_RUNNING)) {
        min_vruntime = scheduler->curr->vruntime;
        found = true;
    }

    for (rb_node_t *node = rb_first(&scheduler->run_tree); node;
         node = rb_next(node)) {
        struct sched_entity *se = rb_entry(node, struct sched_entity, run_node);

        if (!se || !se->on_rq)
            continue;
        if (!found || se->vruntime < min_vruntime)
            min_vruntime = se->vruntime;
        found = true;
    }

    if (found && min_vruntime > scheduler->min_vruntime)
        scheduler->min_vruntime = min_vruntime;
}

static void sched_entity_enqueue_locked(sched_rq_t *scheduler,
                                        struct sched_entity *entity) {
    rb_node_t **slot = &scheduler->run_tree.rb_node;
    rb_node_t *parent = NULL;

    entity->deadline = sched_entity_deadline_locked(scheduler, entity);

    while (*slot) {
        struct sched_entity *curr =
            rb_entry(*slot, struct sched_entity, run_node);
        parent = *slot;
        if (sched_entity_cmp(entity, curr) < 0)
            slot = &(*slot)->rb_left;
        else
            slot = &(*slot)->rb_right;
    }

    sched_run_node_reset(&entity->run_node);
    rb_set_parent(&entity->run_node, parent);
    rb_set_color(&entity->run_node, KRB_RED);
    *slot = &entity->run_node;
    rb_insert_color(&entity->run_node, &scheduler->run_tree);

    entity->on_rq = true;
    entity->rq = scheduler;
    scheduler->nr_queued++;
    scheduler->nr_running++;
    scheduler->load_weight += sched_task_weight(entity->task);
}

static void sched_entity_dequeue_locked(sched_rq_t *scheduler,
                                        struct sched_entity *entity) {
    rb_erase(&entity->run_node, &scheduler->run_tree);
    sched_run_node_reset(&entity->run_node);

    entity->on_rq = false;
    entity->rq = NULL;
    if (scheduler->nr_queued)
        scheduler->nr_queued--;
    if (scheduler->nr_running)
        scheduler->nr_running--;

    uint64_t weight = sched_task_weight(entity->task);
    scheduler->load_weight =
        scheduler->load_weight > weight ? scheduler->load_weight - weight : 0;
    sched_update_min_vruntime_locked(scheduler);
}

static void sched_entity_reweight_current_locked(sched_rq_t *scheduler,
                                                 struct sched_entity *entity,
                                                 uint64_t old_weight,
                                                 int new_nice,
                                                 uint64_t now_ns) {
    if (!scheduler || !entity)
        return;

    task_t *task = entity->task;
    if (!task)
        return;

    if (task->last_sched_in_ns && now_ns > task->last_sched_in_ns) {
        uint64_t delta_ns = now_ns - task->last_sched_in_ns;

        task->last_sched_in_ns = now_ns;
        task->user_time_ns += delta_ns;
        if (old_weight == SCHED_NICE_0_LOAD)
            entity->vruntime += delta_ns;
        else
            entity->vruntime += (delta_ns * SCHED_NICE_0_LOAD) / old_weight;
    }

    task->nice = new_nice;
    uint64_t new_weight = sched_task_weight(entity->task);

    scheduler->load_weight = scheduler->load_weight > old_weight
                                 ? scheduler->load_weight - old_weight
                                 : 0;
    scheduler->load_weight += new_weight;

    entity->slice_ns = sched_entity_slice_locked(scheduler, entity);
    entity->deadline = sched_entity_deadline_locked(scheduler, entity);
}

static void sched_curr_attach_locked(sched_rq_t *scheduler,
                                     struct sched_entity *entity,
                                     uint64_t now_ns) {
    scheduler->curr = entity;
    entity->rq = scheduler;
    entity->on_rq = false;
    scheduler->nr_running++;
    scheduler->load_weight += sched_task_weight(entity->task);
    entity->exec_start_ns = now_ns;
    entity->slice_ns = sched_entity_slice_locked(scheduler, entity);
    entity->deadline = sched_entity_deadline_locked(scheduler, entity);
}

static void sched_curr_detach_locked(sched_rq_t *scheduler,
                                     struct sched_entity *entity) {
    if (scheduler->curr == entity)
        scheduler->curr = scheduler->idle;

    if (scheduler->nr_running)
        scheduler->nr_running--;

    uint64_t weight = sched_task_weight(entity->task);
    scheduler->load_weight =
        scheduler->load_weight > weight ? scheduler->load_weight - weight : 0;
    entity->rq = NULL;
    entity->on_rq = false;
    sched_update_min_vruntime_locked(scheduler);
}

static bool sched_entity_is_current_locked(sched_rq_t *scheduler,
                                           struct sched_entity *entity) {
    return scheduler && entity && scheduler->curr == entity && !entity->on_rq &&
           entity->rq == scheduler;
}

static void sched_add_entity(task_t *task, sched_rq_t *scheduler, bool wakeup) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;
    bool should_ping_cpu = false;
    task_t *resched_task = NULL;
    uint32_t target_cpu = task->cpu_id;

    raw_spin_lock(&scheduler->lock);

    entity->task = task;

    if (scheduler->idle == entity) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    if (entity->on_rq || sched_entity_is_current_locked(scheduler, entity)) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    if (entity->rq && entity->rq != scheduler) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    uint64_t placement = scheduler->min_vruntime;
    if (wakeup && placement > SCHED_WAKEUP_GRANULARITY_NS)
        placement -= SCHED_WAKEUP_GRANULARITY_NS;
    if (entity->vruntime < placement)
        entity->vruntime = placement;

    sched_entity_enqueue_locked(scheduler, entity);
    sched_update_min_vruntime_locked(scheduler);

    if (scheduler->curr && scheduler->curr != scheduler->idle &&
        scheduler->curr->task && scheduler->curr->task != task)
        resched_task = scheduler->curr->task;
    should_ping_cpu = target_cpu < cpu_count && target_cpu != current_cpu_id &&
                      (scheduler->curr == scheduler->idle || wakeup);

    raw_spin_unlock(&scheduler->lock);

    if (resched_task)
        task_set_need_resched(resched_task);
    if (should_ping_cpu)
        irq_trigger_sched_ipi(target_cpu);
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    sched_add_entity(task, scheduler, false);
}

void add_sched_entity_wakeup(task_t *task, sched_rq_t *scheduler) {
    sched_add_entity(task, scheduler, true);
}

void remove_sched_entity(task_t *task, sched_rq_t *scheduler) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (entity->on_rq && entity->rq == scheduler) {
        sched_entity_dequeue_locked(scheduler, entity);
    } else if (sched_entity_is_current_locked(scheduler, entity)) {
        sched_curr_detach_locked(scheduler, entity);
    }

    raw_spin_unlock(&scheduler->lock);
}

void sched_requeue_current(task_t *task, sched_rq_t *scheduler) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (scheduler->idle != entity &&
        sched_entity_is_current_locked(scheduler, entity)) {
        sched_curr_detach_locked(scheduler, entity);
        if (entity->vruntime < scheduler->min_vruntime)
            entity->vruntime = scheduler->min_vruntime;
        sched_entity_enqueue_locked(scheduler, entity);
    }

    raw_spin_unlock(&scheduler->lock);
}

void sched_account_runtime(task_t *task, uint64_t delta_ns) {
    if (!task || !task->sched_info || !delta_ns)
        return;

    struct sched_entity *entity = task->sched_info;
    sched_rq_t *scheduler = entity->rq;

    if (!scheduler && task->cpu_id < MAX_CPU_NUM)
        scheduler = &schedulers[task->cpu_id];
    if (!scheduler)
        return;

    raw_spin_lock(&scheduler->lock);

    bool was_queued = entity->on_rq && entity->rq == scheduler;
    if (was_queued)
        sched_entity_dequeue_locked(scheduler, entity);

    entity->vruntime += sched_calc_delta_fair(delta_ns, task);

    if (sched_entity_is_current_locked(scheduler, entity)) {
        entity->slice_ns = sched_entity_slice_locked(scheduler, entity);
        entity->deadline = sched_entity_deadline_locked(scheduler, entity);
    }

    if (was_queued)
        sched_entity_enqueue_locked(scheduler, entity);

    sched_update_min_vruntime_locked(scheduler);

    raw_spin_unlock(&scheduler->lock);
}

void sched_set_task_nice(task_t *task, int niceval) {
    if (!task)
        return;

    if (niceval < SCHED_NICE_MIN)
        niceval = SCHED_NICE_MIN;
    if (niceval > SCHED_NICE_MAX)
        niceval = SCHED_NICE_MAX;

    if (task->nice == niceval)
        return;

    struct sched_entity *entity = task->sched_info;
    uint64_t now_ns = nano_time();

    if (!entity) {
        task->nice = niceval;
        return;
    }

    sched_rq_t *scheduler = entity->rq;
    if (!scheduler && task->cpu_id < MAX_CPU_NUM)
        scheduler = &schedulers[task->cpu_id];
    if (!scheduler) {
        task->nice = niceval;
        return;
    }

    raw_spin_lock(&scheduler->lock);

    if (entity->on_rq && entity->rq == scheduler) {
        sched_entity_dequeue_locked(scheduler, entity);
        task->nice = niceval;
        sched_entity_enqueue_locked(scheduler, entity);
    } else if (sched_entity_is_current_locked(scheduler, entity)) {
        uint64_t old_weight = sched_nice_weight(task->nice);
        sched_entity_reweight_current_locked(scheduler, entity, old_weight,
                                             niceval, now_ns);
    } else {
        task->nice = niceval;
    }

    sched_update_min_vruntime_locked(scheduler);

    raw_spin_unlock(&scheduler->lock);
}

static struct sched_entity *sched_pick_eevdf_locked(sched_rq_t *scheduler,
                                                    task_t *excluded) {
    struct sched_entity *best = NULL;
    struct sched_entity *min_vruntime = NULL;

    for (rb_node_t *node = rb_first(&scheduler->run_tree); node;
         node = rb_next(node)) {
        struct sched_entity *se = rb_entry(node, struct sched_entity, run_node);
        task_t *candidate = se ? se->task : NULL;

        if (!candidate || candidate->state != TASK_READY)
            continue;
        if (candidate == excluded)
            continue;
        if (!min_vruntime || se->vruntime < min_vruntime->vruntime)
            min_vruntime = se;
        if (sched_entity_eligible_locked(scheduler, se)) {
            best = se;
            break;
        }
    }

    return best ? best : min_vruntime;
}

static void sched_drop_dead_queued_locked(sched_rq_t *scheduler) {
    rb_node_t *node = rb_first(&scheduler->run_tree);

    while (node) {
        struct sched_entity *se = rb_entry(node, struct sched_entity, run_node);
        rb_node_t *next = rb_next(node);
        task_t *task = se ? se->task : NULL;

        if (!task || task->state != TASK_READY) {
            sched_entity_dequeue_locked(scheduler, se);
            node = rb_first(&scheduler->run_tree);
            continue;
        }

        node = next;
    }
}

bool sched_should_preempt(sched_rq_t *scheduler, task_t *curr_task,
                          uint64_t now_ns) {
    bool should_preempt = false;

    if (!scheduler || !curr_task || !curr_task->sched_info)
        return true;

    struct sched_entity *curr = curr_task->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (scheduler->idle && curr_task == scheduler->idle->task) {
        should_preempt = scheduler->nr_queued != 0;
        goto out;
    }

    if (curr_task->state != TASK_READY ||
        curr_task->current_state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (!scheduler->nr_queued)
        goto out;

    if (!sched_entity_is_current_locked(scheduler, curr)) {
        should_preempt = true;
        goto out;
    }

    if (!curr->exec_start_ns || now_ns < curr->exec_start_ns)
        curr->exec_start_ns = now_ns;

    uint64_t ran_ns = now_ns - curr->exec_start_ns;
    uint64_t slice_ns = curr->slice_ns
                            ? curr->slice_ns
                            : sched_entity_slice_locked(scheduler, curr);
    rb_node_t *first = rb_first(&scheduler->run_tree);
    if (!first)
        goto out;

    struct sched_entity *next = rb_entry(first, struct sched_entity, run_node);
    if (!next || !next->task || next->task == curr_task ||
        next->task->state != TASK_READY)
        goto out;

    if (next->deadline + SCHED_WAKEUP_PREEMPT_GRANULARITY_NS < curr->deadline) {
        should_preempt = true;
        goto out;
    }

    if (ran_ns >= slice_ns)
        should_preempt = true;

out:
    raw_spin_unlock(&scheduler->lock);
    return should_preempt;
}

bool sched_should_preempt_on_wakeup(sched_rq_t *scheduler,
                                    task_t *wakeup_task) {
    bool should_preempt = false;

    if (!scheduler || !wakeup_task || !wakeup_task->sched_info)
        return false;

    struct sched_entity *wakeup = wakeup_task->sched_info;

    raw_spin_lock(&scheduler->lock);

    struct sched_entity *curr = scheduler->curr;
    if (!curr || !curr->task || curr == scheduler->idle) {
        should_preempt = true;
        goto out;
    }

    if (curr->task == wakeup_task)
        goto out;

    if (curr->task->state != TASK_READY ||
        curr->task->current_state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (wakeup->deadline + SCHED_WAKEUP_PREEMPT_GRANULARITY_NS < curr->deadline)
        should_preempt = true;

out:
    raw_spin_unlock(&scheduler->lock);
    return should_preempt;
}

bool sched_request_preempt_on_wakeup(sched_rq_t *scheduler,
                                     task_t *wakeup_task) {
    bool should_preempt = false;
    task_t *curr_task = NULL;

    if (!scheduler || !wakeup_task || !wakeup_task->sched_info)
        return false;

    struct sched_entity *wakeup = wakeup_task->sched_info;

    raw_spin_lock(&scheduler->lock);

    struct sched_entity *curr = scheduler->curr;
    if (!curr || !curr->task || curr == scheduler->idle) {
        should_preempt = true;
        curr_task = curr ? curr->task : NULL;
        goto out;
    }

    curr_task = curr->task;
    if (curr_task == wakeup_task)
        goto out;

    if (curr_task->state != TASK_READY ||
        curr_task->current_state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (wakeup->on_rq && wakeup->rq == scheduler)
        should_preempt = true;
    else if (wakeup->deadline + SCHED_WAKEUP_PREEMPT_GRANULARITY_NS <
             curr->deadline)
        should_preempt = true;

out:
    if (should_preempt && curr_task)
        task_set_need_resched(curr_task);
    raw_spin_unlock(&scheduler->lock);
    return should_preempt;
}

uint64_t sched_next_preempt_deadline(sched_rq_t *scheduler, task_t *curr_task,
                                     uint64_t now_ns) {
    uint64_t deadline = UINT64_MAX;

    if (!scheduler || !curr_task || !curr_task->sched_info)
        return now_ns;

    struct sched_entity *curr = curr_task->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (scheduler->idle && curr == scheduler->idle)
        goto out;
    if (!sched_entity_is_current_locked(scheduler, curr))
        goto out_now;
    if (curr_task->state != TASK_READY ||
        curr_task->current_state != TASK_RUNNING)
        goto out_now;
    if (!scheduler->nr_queued)
        goto out;

    uint64_t slice_ns = curr->slice_ns
                            ? curr->slice_ns
                            : sched_entity_slice_locked(scheduler, curr);
    uint64_t start_ns = curr->exec_start_ns ? curr->exec_start_ns : now_ns;

    if (now_ns >= start_ns + slice_ns)
        goto out_now;
    deadline = start_ns + slice_ns;
    goto out;

out_now:
    deadline = now_ns;
out:
    raw_spin_unlock(&scheduler->lock);
    return deadline;
}

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    task_t *next_task = NULL;
    uint64_t now_ns = nano_time();

    raw_spin_lock(&scheduler->lock);

    sched_drop_dead_queued_locked(scheduler);

    struct sched_entity *next = sched_pick_eevdf_locked(scheduler, excluded);
    if (next) {
        if (scheduler->curr == scheduler->idle && scheduler->idle) {
            scheduler->idle->rq = NULL;
            scheduler->idle->on_rq = false;
        }
        sched_entity_dequeue_locked(scheduler, next);
        sched_curr_attach_locked(scheduler, next, now_ns);
        next_task = next->task;
        goto out;
    }

    if (scheduler->idle) {
        scheduler->curr = scheduler->idle;
        scheduler->idle->rq = scheduler;
        scheduler->idle->on_rq = false;
        scheduler->idle->exec_start_ns = now_ns;
        scheduler->idle->slice_ns = 0;
        scheduler->idle->deadline = scheduler->min_vruntime;
        next_task = scheduler->idle->task;
    }

out:
    sched_update_min_vruntime_locked(scheduler);
    raw_spin_unlock(&scheduler->lock);
    return next_task;
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    return sched_pick_next_task_internal(scheduler, NULL);
}

task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded) {
    return sched_pick_next_task_internal(scheduler, excluded);
}

size_t sched_rq_nr_running(sched_rq_t *scheduler) {
    size_t nr_running = 0;

    if (!scheduler)
        return 0;

    raw_spin_lock(&scheduler->lock);
    nr_running = scheduler->nr_running;
    raw_spin_unlock(&scheduler->lock);
    return nr_running;
}

size_t sched_rq_nr_queued(sched_rq_t *scheduler) {
    size_t nr_queued = 0;

    if (!scheduler)
        return 0;

    raw_spin_lock(&scheduler->lock);
    nr_queued = scheduler->nr_queued;
    raw_spin_unlock(&scheduler->lock);
    return nr_queued;
}
