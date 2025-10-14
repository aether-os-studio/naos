/**
 * CP_Kernel 精简版 EEVDF 最小虚拟截止时间优先调度
 */
#include <task/eevdf.h>

unsigned int sysctl_sched_base_slice =
    1000000000ULL / SCHED_HZ; // 默认时间片长度

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

static uint64_t mul_u64_u32_shr(uint64_t a, uint32_t mul, unsigned int shift) {
    return (uint64_t)(((unsigned __int128)a * mul) >> shift);
}

static inline void avg_vruntime_update(eevdf_t *eevdf_sched, uint64_t delta) {
    eevdf_sched->avg_vruntime -= eevdf_sched->avg_load * delta;
}

static inline int64_t entity_key(eevdf_t *eevdf_sched,
                                 struct sched_entity *entity) {
    return (int64_t)(entity->vruntime - eevdf_sched->min_vruntime);
}

static inline bool entity_before(const struct sched_entity *a,
                                 const struct sched_entity *b) {
    return (int64_t)(a->deadline - b->deadline) < 0;
}

static int vruntime_eligible(eevdf_t *eevdf_sched, uint64_t vruntime) {
    struct sched_entity *curr = eevdf_sched->current;
    int64_t avg = eevdf_sched->avg_vruntime;
    long load = eevdf_sched->avg_load;
    if (curr && curr->on_rq) {
        unsigned long weight = scale_load_down(curr->load.weight);
        avg += entity_key(eevdf_sched, curr) * weight;
        load += weight;
    }
    return avg >= (int64_t)(vruntime - eevdf_sched->min_vruntime) * load;
}

void insert_sched_entity(eevdf_t *eevdf_sched, struct sched_entity *se) {
    struct rb_root *root = eevdf_sched->root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *parent = NULL;
    bool leftmost = true;

    while (*link) {
        parent = *link;
        struct sched_entity *entry =
            container_of(parent, struct sched_entity, run_node);

        if (se->deadline < entry->deadline) {
            link = &(*link)->rb_left;
        } else {
            link = &(*link)->rb_right;
            leftmost = false;
        }
    }

    rb_link_node(&se->run_node, parent, link);
    rb_insert_color(&se->run_node, root);

    if (leftmost)
        eevdf_sched->leftmost = &se->run_node;
}

struct sched_entity *pick_earliest_entity(eevdf_t *eevdf_sched) {
    struct rb_node *node = eevdf_sched->leftmost;
    if (!node)
        return NULL;
    return container_of(node, struct sched_entity, run_node);
}

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
    unsigned long w;

    if (lw->inv_weight)
        return;

    w = scale_load_down(lw->weight);

    if ((w >= WMULT_CONST) != 0)
        lw->inv_weight = 1;
    else if (!w)
        lw->inv_weight = WMULT_CONST;
    else
        lw->inv_weight = WMULT_CONST / w;
}

int fls(unsigned int x) {
    if (x == 0)
        return 0;
    return 32 - __builtin_clz(x);
}

static uint64_t __calc_delta(uint64_t delta_exec, unsigned long weight,
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

static inline uint64_t min_vruntime(uint64_t min_vruntime, uint64_t vruntime) {
    int64_t delta = (int64_t)(vruntime - min_vruntime);
    if (delta < 0)
        min_vruntime = vruntime;
    return min_vruntime;
}

static inline bool need_reinsert(struct rb_node *node, uint64_t new_deadline) {
    struct rb_node *parent = rb_parent(node);
    struct rb_node *left = node->rb_left;
    struct rb_node *right = node->rb_right;

    // 检查是否仍然满足红黑树顺序
    if (parent) {
        struct sched_entity *parent_se =
            container_of(parent, struct sched_entity, run_node);
        if (parent->rb_left == node) {
            // 我是父节点的左子节点
            if (new_deadline >= parent_se->deadline)
                return true;
        } else {
            // 我是父节点的右子节点
            if (new_deadline < parent_se->deadline)
                return true;
        }
    }

    // 检查左子节点
    if (left) {
        struct sched_entity *left_se =
            container_of(left, struct sched_entity, run_node);
        if (new_deadline < left_se->deadline)
            return true;
    }

    // 检查右子节点
    if (right) {
        struct sched_entity *right_se =
            container_of(right, struct sched_entity, run_node);
        if (new_deadline >= right_se->deadline)
            return true;
    }

    return false;
}

static bool update_deadline(eevdf_t *eevdf_sched, struct sched_entity *se) {
    if ((int64_t)(se->vruntime - se->deadline) < 0)
        return false;

    if (!se->custom_slice)
        se->slice = sysctl_sched_base_slice;

    uint64_t old_deadline = se->deadline;
    uint64_t new_deadline = se->vruntime + calc_delta_fair(se->slice, se);

    // 如果deadline没变，直接返回
    if (new_deadline == old_deadline) {
        return false;
    }

    // 如果是leftmost且deadline增加，可能不需要重新插入
    struct rb_node *node = &se->run_node;
    if (eevdf_sched->leftmost == node && new_deadline > old_deadline) {
        // 检查是否仍然是最小的
        struct rb_node *next = rb_next(node);
        if (!next) {
            // 只有一个节点，不需要重新插入
            se->deadline = new_deadline;
            return false;
        }

        struct sched_entity *next_se =
            container_of(next, struct sched_entity, run_node);
        if (new_deadline < next_se->deadline) {
            // 仍然是最小的，不需要重新插入
            se->deadline = new_deadline;
            return false;
        }
    }

    se->deadline = new_deadline;
    return true;
}

struct sched_entity *new_entity(task_t *task, uint64_t prio,
                                eevdf_t *eevdf_sched) {
    struct sched_entity *entity =
        (struct sched_entity *)malloc(sizeof(struct sched_entity));
    entity->is_idle = prio == NICE_TO_PRIO(20);
    entity->prio = prio;
    entity->slice = sysctl_sched_base_slice;
    entity->custom_slice = 0;
    entity->on_rq = true;
    entity->deadline = 0;
    entity->vruntime = eevdf_sched->min_vruntime;
    entity->exec_start = nanoTime();
    entity->is_yield = false;
    set_load_weight(entity);
    update_deadline(eevdf_sched, entity);
    entity->thread = task;
    return entity;
}

void change_entity_weight(eevdf_t *eevdf_sched, task_t *thread, uint64_t prio) {
    struct sched_entity *entity = (struct sched_entity *)thread->sched_info;
    if (entity->prio == prio)
        return;

    spin_lock(&eevdf_sched->queue_lock);

    entity->is_idle = prio == NICE_TO_PRIO(20);
    entity->prio = prio;

    unsigned long old_weight = entity->load.weight;
    set_load_weight(entity);

    // 只有权重真正改变时才需要重新计算deadline
    if (old_weight != entity->load.weight) {
        bool was_leftmost = (eevdf_sched->leftmost == &entity->run_node);
        rb_erase(&entity->run_node, eevdf_sched->root);

        if (was_leftmost)
            eevdf_sched->leftmost = NULL;

        // 重新计算deadline
        update_deadline(eevdf_sched, entity);
        insert_sched_entity(eevdf_sched, entity);
    }

    spin_unlock(&eevdf_sched->queue_lock);
}

struct sched_entity *pick_eevdf(eevdf_t *eevdf_sched) {
    struct sched_entity *se = pick_earliest_entity(eevdf_sched);
    struct sched_entity *curr = eevdf_sched->current;
    struct sched_entity *best = NULL;
    struct rb_node *node = eevdf_sched->root->rb_node;

    if (se && vruntime_eligible(eevdf_sched, se->vruntime)) {
        best = se;
        goto found;
    }

    while (node) {
        struct rb_node *left = node->rb_left;
        if (left &&
            vruntime_eligible(eevdf_sched,
                              container_of(left, struct sched_entity, run_node)
                                  ->min_vruntime)) {
            node = left;
            continue;
        }
        se = container_of(node, struct sched_entity, run_node);
        if (vruntime_eligible(eevdf_sched, se->vruntime)) {
            best = se;
            break;
        }
        node = node->rb_right;
    }

found:;
    if (!best || (curr && entity_before(curr, best)))
        best = curr;

    return best;
}

static uint64_t __update_min_vruntime(eevdf_t *eevdf_sched, uint64_t vruntime) {
    uint64_t min_vruntime = eevdf_sched->min_vruntime;
    int64_t delta = (int64_t)(vruntime - min_vruntime);
    if (delta > 0) {
        avg_vruntime_update(eevdf_sched, delta);
        min_vruntime = vruntime;
    }
    return min_vruntime;
}

static void update_min_vruntime(eevdf_t *eevdf_sched) {
    struct sched_entity *curr = eevdf_sched->current;
    struct sched_entity *se = NULL;
    uint64_t vruntime = eevdf_sched->min_vruntime;

    if (eevdf_sched->root->rb_node)
        se = container_of(eevdf_sched->root->rb_node, struct sched_entity,
                          run_node);

    if (curr && curr->on_rq) {
        vruntime = curr->vruntime;
    } else {
        curr = NULL;
    }

    if (se) {
        if (!curr)
            vruntime = se->min_vruntime;
        else
            vruntime = min_vruntime(vruntime, se->vruntime);
    }

    eevdf_sched->min_vruntime =
        MAX(__update_min_vruntime(eevdf_sched, vruntime), vruntime);
}

static int64_t update_curr_se(struct sched_entity *curr) {
    uint64_t now = nanoTime();
    int64_t delta_exec;

    delta_exec = now - curr->exec_start;
    if (delta_exec <= 0)
        return delta_exec;

    curr->exec_start = now;
    curr->sum_exec_runtime += delta_exec;
    return delta_exec;
}

void update_current_task(eevdf_t *eevdf_sched) {
    struct sched_entity *curr = eevdf_sched->current;
    if (!curr)
        return;

    int64_t delta_exec;
    bool need_reinsert = false;

    if (curr->is_yield) {
        curr->vruntime = curr->deadline;
        need_reinsert = update_deadline(eevdf_sched, curr);
        curr->is_yield = false;
    } else {
        delta_exec = update_curr_se(curr);
        if (delta_exec <= 0)
            return;

        curr->vruntime += calc_delta_fair(delta_exec, curr);
        need_reinsert = update_deadline(eevdf_sched, curr);
        update_min_vruntime(eevdf_sched);
    }

    if (need_reinsert) {
        bool was_leftmost = (eevdf_sched->leftmost == &curr->run_node);
        rb_erase(&curr->run_node, eevdf_sched->root);

        if (was_leftmost)
            eevdf_sched->leftmost = NULL;

        insert_sched_entity(eevdf_sched, curr);
    }
}

void add_eevdf_entity_with_prio(task_t *new_task, uint64_t prio,
                                eevdf_t *eevdf_sched) {
    struct sched_entity *entity = new_entity(new_task, prio, eevdf_sched);
    entity->handle = eevdf_sched;
    new_task->sched_info = entity;

    spin_lock(&eevdf_sched->queue_lock);
    insert_sched_entity(eevdf_sched, entity);
    spin_unlock(&eevdf_sched->queue_lock);

    eevdf_sched->task_count++;
}

void remove_sched_entity(eevdf_t *eevdf_sched, struct sched_entity *se) {
    struct rb_root *root = eevdf_sched->root;
    bool was_leftmost = (eevdf_sched->leftmost == &se->run_node);

    rb_erase(&se->run_node, root);

    if (was_leftmost)
        eevdf_sched->leftmost = rb_first(root);

    if (eevdf_sched->current == se)
        eevdf_sched->current = NULL;
}

void remove_eevdf_entity(task_t *thread, eevdf_t *eevdf_sched) {
    struct sched_entity *entity = (struct sched_entity *)thread->sched_info;

    spin_lock(&eevdf_sched->queue_lock);
    remove_sched_entity(eevdf_sched, entity);
    spin_unlock(&eevdf_sched->queue_lock);

    eevdf_sched->task_count--;
}

task_t *pick_next_task(eevdf_t *eevdf_sched) {
    spin_lock(&eevdf_sched->queue_lock);

    update_current_task(eevdf_sched);

    // 如果current被删除了，这里才pick
    struct sched_entity *current = eevdf_sched->current;
    if (!current)
        current = pick_eevdf(eevdf_sched);
    else
        current = pick_eevdf(eevdf_sched); // 每次都要pick最合适的

    spin_unlock(&eevdf_sched->queue_lock);

    if (current) {
        current->exec_start = nanoTime();
        eevdf_sched->current = current;
        return current->thread;
    }

    return NULL;
}
