#include "task/sched.h"

static inline list_node_t *sched_queue_head(list_queue_t *queue) {
    return __atomic_load_n(&queue->head, __ATOMIC_ACQUIRE);
}

static inline list_node_t *sched_node_next(list_node_t *node) {
    return __atomic_load_n(&node->next, __ATOMIC_ACQUIRE);
}

static inline struct sched_entity *sched_node_entity(list_node_t *node) {
    return (struct sched_entity *)__atomic_load_n(&node->data,
                                                  __ATOMIC_ACQUIRE);
}

static inline bool sched_entity_on_rq(struct sched_entity *entity) {
    return __atomic_load_n(&entity->on_rq, __ATOMIC_ACQUIRE);
}

static list_node_t *
sched_entity_node_get_or_create(struct sched_entity *entity) {
    list_node_t *node = __atomic_load_n(&entity->node, __ATOMIC_ACQUIRE);
    if (node)
        return node;

    list_node_t *new_node = calloc(1, sizeof(list_node_t));
    if (!new_node)
        return NULL;

    new_node->data = entity;
    list_node_t *expected = NULL;
    if (!__atomic_compare_exchange_n(&entity->node, &expected, new_node, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        free(new_node);
        return expected;
    }

    return new_node;
}

static void sched_queue_enqueue_lockfree(list_queue_t *queue,
                                         list_node_t *node) {
    node->next = NULL;
    node->prev = NULL;

    list_node_t *prev =
        __atomic_exchange_n(&queue->tail, node, __ATOMIC_ACQ_REL);

    if (prev) {
        node->prev = prev;
        __atomic_store_n(&prev->next, node, __ATOMIC_RELEASE);
    } else {
        __atomic_store_n(&queue->head, node, __ATOMIC_RELEASE);
    }
}

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    struct sched_entity *entity =
        __atomic_load_n(&scheduler->curr, __ATOMIC_RELAXED);
    list_node_t *head =
        __atomic_load_n(&scheduler->sched_queue->head, __ATOMIC_ACQUIRE);

    if (__builtin_expect(!head, 0)) {
        __atomic_store_n(&scheduler->curr, scheduler->idle, __ATOMIC_RELAXED);
        return scheduler->idle->task;
    }

    list_node_t *nextL;
    if (!entity || entity == scheduler->idle ||
        !__atomic_load_n(&entity->on_rq, __ATOMIC_RELAXED)) {
        nextL = head;
    } else {
        list_node_t *entity_node =
            __atomic_load_n(&entity->node, __ATOMIC_RELAXED);
        nextL = entity_node
                    ? __atomic_load_n(&entity_node->next, __ATOMIC_ACQUIRE)
                    : head;
        if (!nextL)
            nextL = head;
    }

    list_node_t *start = nextL;
    do {
        struct sched_entity *next = (struct sched_entity *)__atomic_load_n(
            &nextL->data, __ATOMIC_RELAXED);
        if (__builtin_expect(
                next && __atomic_load_n(&next->on_rq, __ATOMIC_RELAXED), 1)) {
            task_t *next_task = __atomic_load_n(&next->task, __ATOMIC_RELAXED);
            if (next_task && next_task->state == TASK_READY &&
                next_task != excluded) {
                __atomic_store_n(&scheduler->curr, next, __ATOMIC_RELAXED);
                return next_task;
            }
        }

        nextL = __atomic_load_n(&nextL->next, __ATOMIC_ACQUIRE);
        if (!nextL)
            nextL = head;
    } while (nextL != start);

    __atomic_store_n(&scheduler->curr, scheduler->idle, __ATOMIC_RELAXED);
    return scheduler->idle->task;
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;
    __atomic_store_n(&entity->task, task, __ATOMIC_RELAXED);

    bool expected_on_rq = false;
    if (!__atomic_compare_exchange_n(&entity->on_rq, &expected_on_rq, true,
                                     false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        return;

    list_node_t *node = sched_entity_node_get_or_create(entity);
    if (!node) {
        __atomic_store_n(&entity->on_rq, false, __ATOMIC_RELAXED);
        return;
    }

    bool expected_once = false;
    if (__atomic_compare_exchange_n(&entity->queued_once, &expected_once, true,
                                    false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        sched_queue_enqueue_lockfree(scheduler->sched_queue, node);
}

void remove_sched_entity(task_t *thread, sched_rq_t *scheduler) {
    if (__builtin_expect(!thread || !scheduler || !thread->sched_info, 0))
        return;

    struct sched_entity *entity = thread->sched_info;
    if (!__atomic_exchange_n(&entity->on_rq, false, __ATOMIC_RELAXED))
        return;

    struct sched_entity *curr =
        __atomic_load_n(&scheduler->curr, __ATOMIC_RELAXED);
    if (curr == entity)
        __atomic_store_n(&scheduler->curr, scheduler->idle, __ATOMIC_RELAXED);
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    return sched_pick_next_task_internal(scheduler, NULL);
}

task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded) {
    return sched_pick_next_task_internal(scheduler, excluded);
}
