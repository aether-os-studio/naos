#include "task/sched.h"

extern sched_rq_t schedulers[MAX_CPU_NUM];

#define SCHED_NICE_MIN (-20)
#define SCHED_NICE_MAX 19
#define SCHED_NICE_0_LOAD 1024ULL
#define SCHED_WAKEUP_GRANULARITY_NS 1000000ULL
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

static inline uint64_t sched_calc_delta_fair(uint64_t delta_ns, task_t *task) {
    uint64_t weight = sched_task_weight(task);

    if (!delta_ns || weight == SCHED_NICE_0_LOAD)
        return delta_ns;

    return (delta_ns * SCHED_NICE_0_LOAD) / weight;
}

static inline uint64_t sched_task_slice_ns_locked(sched_rq_t *scheduler,
                                                  task_t *task) {
    uint64_t weight = sched_task_weight(task);
    struct sched_entity *entity = task ? task->sched_info : NULL;
    uint64_t runnable_weight =
        scheduler->load_weight +
        ((!entity || !entity->on_rq || entity->rq != scheduler) ? weight : 0);
    uint64_t slice = SCHED_LATENCY_NS;

    if (runnable_weight)
        slice = (SCHED_LATENCY_NS * weight) / runnable_weight;

    if (slice < SCHED_MIN_GRANULARITY_NS)
        return SCHED_MIN_GRANULARITY_NS;
    if (slice > SCHED_MAX_GRANULARITY_NS)
        return SCHED_MAX_GRANULARITY_NS;
    return slice;
}

static inline void sched_run_node_reset(rb_node_t *node) {
    if (!node)
        return;

    memset(node, 0, sizeof(*node));
}

static int sched_entity_cmp(struct sched_entity *left,
                            struct sched_entity *right) {
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
    rb_node_t *first = rb_first(&scheduler->run_tree);

    if (first) {
        struct sched_entity *leftmost =
            rb_entry(first, struct sched_entity, run_node);
        if (leftmost->vruntime > scheduler->min_vruntime)
            scheduler->min_vruntime = leftmost->vruntime;
    } else if (scheduler->curr && scheduler->curr != scheduler->idle &&
               scheduler->curr->vruntime > scheduler->min_vruntime) {
        scheduler->min_vruntime = scheduler->curr->vruntime;
    }
}

static void sched_entity_enqueue_locked(sched_rq_t *scheduler,
                                        struct sched_entity *entity) {
    rb_node_t **slot = &scheduler->run_tree.rb_node;
    rb_node_t *parent = NULL;

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
    scheduler->nr_running++;
    scheduler->load_weight += sched_task_weight(entity->task);
}

static void sched_entity_dequeue_locked(sched_rq_t *scheduler,
                                        struct sched_entity *entity) {
    rb_erase(&entity->run_node, &scheduler->run_tree);
    sched_run_node_reset(&entity->run_node);

    entity->on_rq = false;
    entity->rq = NULL;
    if (scheduler->nr_running)
        scheduler->nr_running--;
    uint64_t weight = sched_task_weight(entity->task);
    scheduler->load_weight =
        scheduler->load_weight > weight ? scheduler->load_weight - weight : 0;
    sched_update_min_vruntime_locked(scheduler);
}

static void sched_add_entity(task_t *task, sched_rq_t *scheduler, bool wakeup) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;
    entity->task = task;

    raw_spin_lock(&scheduler->lock);

    if (entity->on_rq) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    if (entity->rq && entity->rq != scheduler) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    if (wakeup) {
        uint64_t wake_vruntime = scheduler->min_vruntime;
        if (wake_vruntime > SCHED_WAKEUP_GRANULARITY_NS)
            wake_vruntime -= SCHED_WAKEUP_GRANULARITY_NS;
        entity->vruntime = wake_vruntime;
    } else if (entity->vruntime < scheduler->min_vruntime) {
        entity->vruntime = scheduler->min_vruntime;
    }

    sched_entity_enqueue_locked(scheduler, entity);
    sched_update_min_vruntime_locked(scheduler);

    raw_spin_unlock(&scheduler->lock);
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    sched_add_entity(task, scheduler, false);
}

void add_sched_entity_wakeup(task_t *task, sched_rq_t *scheduler) {
    sched_add_entity(task, scheduler, true);
}

void remove_sched_entity(task_t *thread, sched_rq_t *scheduler) {
    if (__builtin_expect(!thread || !scheduler || !thread->sched_info, 0))
        return;

    struct sched_entity *entity = thread->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (!entity->on_rq || entity->rq != scheduler) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    sched_entity_dequeue_locked(scheduler, entity);

    if (scheduler->curr == entity) {
        scheduler->curr = scheduler->idle;
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

    bool requeue = entity->on_rq && entity->rq == scheduler;
    if (requeue)
        sched_entity_dequeue_locked(scheduler, entity);

    entity->vruntime += sched_calc_delta_fair(delta_ns, task);

    if (requeue)
        sched_entity_enqueue_locked(scheduler, entity);

    sched_update_min_vruntime_locked(scheduler);

    raw_spin_unlock(&scheduler->lock);
}

bool sched_should_preempt(sched_rq_t *scheduler, task_t *curr_task,
                          uint64_t now_ns) {
    bool should_preempt = false;

    if (!scheduler || !curr_task || !curr_task->sched_info)
        return true;

    struct sched_entity *curr = curr_task->sched_info;

    raw_spin_lock(&scheduler->lock);

    if (!scheduler->nr_running)
        goto out;

    if (scheduler->idle && curr_task == scheduler->idle->task) {
        should_preempt = true;
        goto out;
    }

    if (curr_task->state != TASK_READY && curr_task->state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (!curr->slice_start_ns || now_ns < curr->slice_start_ns)
        curr->slice_start_ns = now_ns;

    uint64_t ran_ns = now_ns - curr->slice_start_ns;
    uint64_t slice_ns = sched_task_slice_ns_locked(scheduler, curr_task);
    if (ran_ns < slice_ns)
        goto out;

    rb_node_t *first = rb_first(&scheduler->run_tree);
    if (!first) {
        curr->slice_start_ns = now_ns;
        goto out;
    }

    struct sched_entity *leftmost =
        rb_entry(first, struct sched_entity, run_node);
    if (leftmost->vruntime + SCHED_WAKEUP_GRANULARITY_NS < curr->vruntime) {
        should_preempt = true;
        goto out;
    }

    curr->slice_start_ns = now_ns;

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

    if (curr->task->state != TASK_READY && curr->task->state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (wakeup->vruntime + SCHED_WAKEUP_PREEMPT_GRANULARITY_NS < curr->vruntime)
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

    if (curr_task->state != TASK_READY && curr_task->state != TASK_RUNNING) {
        should_preempt = true;
        goto out;
    }

    if (wakeup->vruntime + SCHED_WAKEUP_PREEMPT_GRANULARITY_NS < curr->vruntime)
        should_preempt = true;

out:
    if (should_preempt && curr_task)
        task_set_need_resched(curr_task);
    raw_spin_unlock(&scheduler->lock);
    return should_preempt;
}

void sched_note_slice_start(task_t *task, uint64_t now_ns) {
    if (!task || !task->sched_info)
        return;

    struct sched_entity *entity = task->sched_info;
    sched_rq_t *scheduler = entity->rq;

    if (!scheduler && task->cpu_id < MAX_CPU_NUM)
        scheduler = &schedulers[task->cpu_id];
    if (!scheduler)
        return;

    raw_spin_lock(&scheduler->lock);
    entity->slice_start_ns = now_ns;
    raw_spin_unlock(&scheduler->lock);
}

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    task_t *next_task = NULL;
    rb_node_t *node;

    raw_spin_lock(&scheduler->lock);

    for (node = rb_first(&scheduler->run_tree); node;) {
        struct sched_entity *next =
            rb_entry(node, struct sched_entity, run_node);
        rb_node_t *next_node = rb_next(node);

        if (__builtin_expect(next && next->on_rq && next->rq == scheduler, 1)) {
            task_t *candidate = next->task;
            if (!candidate || candidate->state != TASK_READY) {
                sched_entity_dequeue_locked(scheduler, next);
                node = rb_first(&scheduler->run_tree);
                continue;
            }
            if (candidate != excluded &&
                (!task_is_on_cpu(candidate) || candidate == current_task)) {
                scheduler->curr = next;
                next->slice_start_ns = nano_time();
                next_task = candidate;
                goto out;
            }
        }
        node = next_node;
    }

    scheduler->curr = scheduler->idle;
    scheduler->idle->slice_start_ns = nano_time();
    next_task = scheduler->idle->task;

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
