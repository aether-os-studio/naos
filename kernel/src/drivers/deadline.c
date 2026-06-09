#include <arch/arch.h>
#include <drivers/deadline.h>
#include <irq/irq_manager.h>

typedef struct deadline_queue {
    rb_root_t tree;
    spinlock_t lock;
    uint64_t next_cached_ns;
} deadline_queue_t;

static deadline_queue_t deadline_queues[MAX_CPU_NUM] = {
    [0 ... MAX_CPU_NUM - 1] =
        {
            .tree = RB_ROOT_INIT,
            .lock = SPIN_INIT,
            .next_cached_ns = UINT64_MAX,
        },
};

static inline deadline_queue_t *deadline_queue_for_cpu(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        cpu_id = 0;
    return &deadline_queues[cpu_id];
}

static int deadline_source_cmp(const deadline_source_t *left,
                               const deadline_source_t *right) {
    if (left->deadline_ns < right->deadline_ns)
        return -1;
    if (left->deadline_ns > right->deadline_ns)
        return 1;
    if (left->type < right->type)
        return -1;
    if (left->type > right->type)
        return 1;
    return left < right ? -1 : (left > right ? 1 : 0);
}

static void deadline_refresh_next_locked(deadline_queue_t *queue) {
    rb_node_t *first = rb_first(&queue->tree);
    uint64_t next = first
                        ? rb_entry(first, deadline_source_t, node)->deadline_ns
                        : UINT64_MAX;
    __atomic_store_n(&queue->next_cached_ns, next, __ATOMIC_RELEASE);
}

void deadline_source_init(deadline_source_t *source,
                          deadline_source_type_t type, uint32_t cpu_id) {
    if (!source)
        return;

    memset(source, 0, sizeof(*source));
    source->deadline_ns = UINT64_MAX;
    source->cpu_id = cpu_id;
    source->type = type;
}

void deadline_source_update(deadline_source_t *source, uint64_t deadline_ns) {
    deadline_queue_t *queue;
    rb_node_t **slot;
    rb_node_t *parent;
    uint64_t old_next;
    uint64_t new_next;
    bool should_reprogram;

    if (!source)
        return;

    queue = deadline_queue_for_cpu(source->cpu_id);
    spin_lock(&queue->lock);
    old_next = __atomic_load_n(&queue->next_cached_ns, __ATOMIC_ACQUIRE);

    if (source->deadline_ns == deadline_ns &&
        source->queued == (deadline_ns != UINT64_MAX)) {
        spin_unlock(&queue->lock);
        return;
    }

    if (source->queued) {
        rb_erase(&source->node, &queue->tree);
        memset(&source->node, 0, sizeof(source->node));
        source->queued = false;
    }

    source->deadline_ns = deadline_ns;
    if (deadline_ns != UINT64_MAX) {
        slot = &queue->tree.rb_node;
        parent = NULL;

        while (*slot) {
            deadline_source_t *curr = rb_entry(*slot, deadline_source_t, node);
            parent = *slot;
            if (deadline_source_cmp(source, curr) < 0)
                slot = &(*slot)->rb_left;
            else
                slot = &(*slot)->rb_right;
        }

        source->node.rb_left = NULL;
        source->node.rb_right = NULL;
        rb_set_parent(&source->node, parent);
        rb_set_color(&source->node, KRB_RED);
        *slot = &source->node;
        rb_insert_color(&source->node, &queue->tree);
        source->queued = true;
    }

    deadline_refresh_next_locked(queue);
    new_next = __atomic_load_n(&queue->next_cached_ns, __ATOMIC_ACQUIRE);
    should_reprogram = new_next < old_next;
    spin_unlock(&queue->lock);

    if (should_reprogram)
        deadline_reprogram_cpu(source->cpu_id);
}

uint64_t deadline_next_ns_for_cpu(uint32_t cpu_id) {
    deadline_queue_t *queue = deadline_queue_for_cpu(cpu_id);
    uint64_t next;

    spin_lock(&queue->lock);
    next = queue->next_cached_ns;
    spin_unlock(&queue->lock);
    return next;
}

uint64_t deadline_cached_next_ns_for_cpu(uint32_t cpu_id) {
    deadline_queue_t *queue = deadline_queue_for_cpu(cpu_id);
    return __atomic_load_n(&queue->next_cached_ns, __ATOMIC_ACQUIRE);
}

void deadline_reprogram_cpu(uint32_t cpu_id) {
    if (cpu_id >= cpu_count)
        return;

    if (cpu_id != current_cpu_id) {
        irq_trigger_sched_ipi(cpu_id);
        return;
    }

    arch_program_timer_deadline_local(deadline_cached_next_ns_for_cpu(cpu_id));
}

void deadline_reprogram_local(void) { deadline_reprogram_cpu(current_cpu_id); }
