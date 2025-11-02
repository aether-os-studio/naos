/**
 * CP_Kernel 精简版 EEVDF 最小虚拟截止时间优先调度
 */
#include <task/eevdf.h>

uint64_t sysctl_sched_base_slice = 1000000000ULL / SCHED_HZ;

const int sched_prio_to_weight[40] = {
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548,  7620,  6100,  4904,  3906,
    /*  -5 */ 3121,  2501,  1991,  1586,  1277,
    /*   0 */ 1024,  820,   655,   526,   423,
    /*   5 */ 335,   272,   215,   172,   137,
    /*  10 */ 110,   87,    70,    56,    45,
    /*  15 */ 36,    29,    23,    18,    15,
};

const uint32_t sched_prio_to_wmult[40] = {
    /* -20 */ 48388,     59856,     76040,     92818,     118348,
    /* -15 */ 147320,    184698,    229616,    287308,    360437,
    /* -10 */ 449829,    563644,    704093,    875809,    1099582,
    /*  -5 */ 1376151,   1717300,   2157191,   2708050,   3363326,
    /*   0 */ 4194304,   5237765,   6557202,   8165337,   10153587,
    /*   5 */ 12820798,  15790321,  19976592,  24970740,  31350126,
    /*  10 */ 39045157,  49367440,  61356676,  76695844,  95443717,
    /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
};

static uint64_t sched_clock() { return nanoTime(); }

static uint64_t mul_u64_u32_shr(uint64_t a, uint32_t mul, unsigned int shift) {
    return (uint64_t)(((unsigned __int128)a * mul) >> shift);
}

static int fls(unsigned int x) {
    if (x == 0)
        return 0;
    return 32 - __builtin_clz(x);
}

static inline uint64_t min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }

static inline uint64_t max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }

void set_load_weight(struct sched_entity *entity) {
    int prio = entity->prio - MAX_RT_PRIO;
    struct load_weight lw;

    if (entity->prio == NICE_TO_PRIO(20)) {
        lw.weight = scale_load(WEIGHT_IDLEPRIO);
        lw.inv_weight = WMULT_IDLEPRIO;
    } else {
        lw.weight = scale_load(sched_prio_to_weight[prio]);
        lw.inv_weight = sched_prio_to_wmult[prio];
    }
    entity->load = lw;
}

static void __update_inv_weight(struct load_weight *lw) {
    uint64_t w;

    if (lw->inv_weight)
        return;

    w = scale_load_down(lw->weight);

    if (w >= WMULT_CONST)
        lw->inv_weight = 1;
    else if (!w)
        lw->inv_weight = WMULT_CONST;
    else
        lw->inv_weight = WMULT_CONST / w;
}

static uint64_t __calc_delta(uint64_t delta_exec, uint64_t weight,
                             struct load_weight *lw) {
    uint64_t fact = scale_load_down(weight);
    uint32_t fact_hi = (uint32_t)(fact >> 32);
    int shift = WMULT_SHIFT;
    int fs;

    __update_inv_weight(lw);

    if (fact_hi) {
        fs = fls(fact_hi);
        shift -= fs;
        fact >>= fs;
    }

    fact = (uint64_t)(fact * lw->inv_weight);

    fact_hi = (uint32_t)(fact >> 32);
    if (fact_hi) {
        fs = fls(fact_hi);
        shift -= fs;
        fact >>= fs;
    }

    return mul_u64_u32_shr(delta_exec, fact, shift);
}

static inline uint64_t calc_delta_fair(uint64_t delta,
                                       struct sched_entity *se) {
    if (se->load.weight != NICE_0_LOAD)
        delta = __calc_delta(delta, NICE_0_LOAD, &se->load);
    return delta;
}

void insert_sched_entity(struct rb_root *root, struct sched_entity *se) {
    struct rb_node **link = &root->rb_node;
    struct rb_node *parent = NULL;

    while (*link) {
        struct sched_entity *entry;
        parent = *link;
        entry = container_of(parent, struct sched_entity, run_node);

        // 按 deadline 排序
        if ((int64_t)(se->deadline - entry->deadline) < 0)
            link = &(*link)->rb_left;
        else
            link = &(*link)->rb_right;
    }

    rb_link_node(&se->run_node, parent, link);
    rb_insert_color(&se->run_node, root);
}

static struct sched_entity *rb_first_entity(struct rb_root *root) {
    struct rb_node *node = rb_first(root);
    if (!node)
        return NULL;
    return container_of(node, struct sched_entity, run_node);
}

static void update_deadline(struct sched_entity *se) {
    if ((int64_t)(se->vruntime - se->deadline) < 0)
        return;

    if (!se->custom_slice)
        se->slice = sysctl_sched_base_slice;

    se->deadline = se->vruntime + calc_delta_fair(se->slice, se);
}

static inline bool entity_eligible(eevdf_t *eevdf_sched,
                                   struct sched_entity *se) {
    int64_t lag = (int64_t)(eevdf_sched->min_vruntime - se->vruntime);
    int64_t limit = -(int64_t)calc_delta_fair(se->slice, se);

    return lag >= limit;
}

struct sched_entity *pick_eevdf(eevdf_t *eevdf_sched) {
    struct rb_node *node = eevdf_sched->root->rb_node;
    struct sched_entity *best = NULL;
    struct sched_entity *curr = eevdf_sched->current;

    if (!node)
        return curr;

    struct sched_entity *earliest = rb_first_entity(eevdf_sched->root);

    if (earliest && entity_eligible(eevdf_sched, earliest)) {
        best = earliest;
        goto check_current;
    }

    int max_search = 64; // 最多搜索 64 个节点
    int search_count = 0;

    node = eevdf_sched->root->rb_node;
    while (node && search_count < max_search) {
        struct sched_entity *se =
            container_of(node, struct sched_entity, run_node);

        if (entity_eligible(eevdf_sched, se)) {
            best = se;
            break;
        }

        if (node->rb_left) {
            node = node->rb_left;
        } else if (node->rb_right) {
            node = node->rb_right;
        } else {
            // 叶子节点，向上回溯找右兄弟
            while (rb_parent(node) && node == rb_parent(node)) {
                node = rb_parent(node);
            }
            if (node->rb_parent_color)
                node = rb_parent(node);
            else
                break;
        }
        search_count++;
    }

    if (!best)
        best = earliest;

check_current:
    if (curr && curr->on_rq) {
        if (!best || (int64_t)(curr->deadline - best->deadline) < 0)
            best = curr;
    }

    return best;
}

static void update_min_vruntime(eevdf_t *eevdf_sched) {
    struct sched_entity *curr = eevdf_sched->current;
    struct sched_entity *leftmost = rb_first_entity(eevdf_sched->root);
    uint64_t vruntime = eevdf_sched->min_vruntime;
    bool updated = false;

    if (curr && curr->on_rq) {
        vruntime = curr->vruntime;
        updated = true;
    }

    if (leftmost) {
        if (!updated) {
            vruntime = leftmost->vruntime;
        } else {
            if ((int64_t)(leftmost->vruntime - vruntime) < 0)
                vruntime = leftmost->vruntime;
        }
    }

    if ((int64_t)(vruntime - eevdf_sched->min_vruntime) > 0) {
        eevdf_sched->min_vruntime = vruntime;
    }
}

static void wrap_vruntime(eevdf_t *eevdf_sched) {
    const uint64_t threshold = (uint64_t)1 << 60;

    if (eevdf_sched->min_vruntime < threshold)
        return;

    uint64_t offset = threshold / 2;
    eevdf_sched->min_vruntime -= offset;

    struct sched_entity *curr = eevdf_sched->current;
    if (curr) {
        if (curr->vruntime > offset)
            curr->vruntime -= offset;
        if (curr->deadline > offset)
            curr->deadline -= offset;
    }

    struct rb_node *node;
    for (node = rb_first(eevdf_sched->root); node; node = rb_next(node)) {
        struct sched_entity *se =
            container_of(node, struct sched_entity, run_node);
        if (se->vruntime > offset)
            se->vruntime -= offset;
        if (se->deadline > offset)
            se->deadline -= offset;
    }
}

static int64_t update_curr_se(struct sched_entity *curr) {
    uint64_t now = sched_clock();
    int64_t delta_exec;

    delta_exec = now - curr->exec_start;
    if (delta_exec <= 0)
        return 0;

    curr->exec_start = now;
    curr->sum_exec_runtime += delta_exec;
    return delta_exec;
}

void update_current_task(eevdf_t *eevdf_sched) {
    struct sched_entity *curr = eevdf_sched->current;
    if (!curr || !curr->on_rq)
        return;

    int64_t delta_exec = update_curr_se(curr);
    if (delta_exec <= 0)
        return;

    uint64_t old_vruntime = curr->vruntime;
    curr->vruntime += calc_delta_fair(delta_exec, curr);

    if (curr->is_yield) {
        curr->vruntime = curr->deadline;
        curr->is_yield = false;
    }

    uint64_t old_deadline = curr->deadline;
    update_deadline(curr);

    bool need_reinsert = false;
    if (old_deadline != curr->deadline) {
        struct rb_node *next = rb_next(&curr->run_node);
        if (next) {
            struct sched_entity *next_se =
                container_of(next, struct sched_entity, run_node);
            if ((int64_t)(curr->deadline - next_se->deadline) > 0)
                need_reinsert = true;
        }
    }

    if (need_reinsert) {
        rb_erase(&curr->run_node, eevdf_sched->root);
        insert_sched_entity(eevdf_sched->root, curr);
    }

    update_min_vruntime(eevdf_sched);

    wrap_vruntime(eevdf_sched);
}

struct sched_entity *new_entity(task_t *task, uint64_t prio,
                                eevdf_t *eevdf_sched) {
    struct sched_entity *entity =
        (struct sched_entity *)malloc(sizeof(struct sched_entity));
    if (!entity)
        return NULL;

    memset(entity, 0, sizeof(struct sched_entity));

    entity->is_idle = (prio == NICE_TO_PRIO(20));
    entity->prio = prio;
    entity->slice = sysctl_sched_base_slice;
    entity->custom_slice = 0;
    entity->on_rq = true;
    entity->exec_start = sched_clock();
    entity->is_yield = false;
    entity->thread = task;

    set_load_weight(entity);

    entity->vruntime = eevdf_sched->min_vruntime;
    entity->deadline = eevdf_sched->min_vruntime;

    return entity;
}

void add_eevdf_entity_with_prio(task_t *new_task, uint64_t prio,
                                eevdf_t *eevdf_sched) {
    struct sched_entity *entity = new_entity(new_task, prio, eevdf_sched);
    if (!entity)
        return;

    entity->handle = eevdf_sched;
    new_task->sched_info = entity;

    spin_lock(&eevdf_sched->queue_lock);
    insert_sched_entity(eevdf_sched->root, entity);
    eevdf_sched->task_count++;
    update_min_vruntime(eevdf_sched);
    spin_unlock(&eevdf_sched->queue_lock);
}

void remove_sched_entity(eevdf_t *eevdf_sched, struct rb_root *root,
                         struct sched_entity *se) {
    if (!se || !root)
        return;

    spin_lock(&eevdf_sched->queue_lock);

    se->on_rq = false;

    rb_erase(&se->run_node, root);

    RB_CLEAR_NODE(&se->run_node);

    if (eevdf_sched->current == se) {
        if (eevdf_sched->idle_entity) {
            eevdf_sched->current = eevdf_sched->idle_entity;
        } else {
            eevdf_sched->current = NULL;
        }
    }

    update_min_vruntime(eevdf_sched);

    spin_unlock(&eevdf_sched->queue_lock);
}

void remove_eevdf_entity(task_t *thread, eevdf_t *eevdf_sched) {
    if (!thread || !eevdf_sched)
        return;

    struct sched_entity *entity = (struct sched_entity *)thread->sched_info;
    if (!entity)
        return;

    remove_sched_entity(eevdf_sched, eevdf_sched->root, entity);

    eevdf_sched->task_count--;

    thread->sched_info = NULL;

    free(entity);
}

task_t *pick_next_task(eevdf_t *eevdf_sched) {
    spin_lock(&eevdf_sched->queue_lock);

    update_current_task(eevdf_sched);

    struct sched_entity *next = pick_eevdf(eevdf_sched);

    if (!next)
        next = eevdf_sched->idle_entity;

    next->exec_start = sched_clock();
    eevdf_sched->current = next;

    spin_unlock(&eevdf_sched->queue_lock);

    return next->thread;
}
