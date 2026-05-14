#include "task/sched.h"

static inline list_node_t *sched_queue_head(list_queue_t *queue) {
    return queue ? queue->head : NULL;
}

static inline void sched_node_reset(list_node_t *node) {
    if (!node)
        return;

    node->prev = node;
    node->next = node;
}

static inline void sched_queue_enqueue_locked(list_queue_t *queue,
                                              list_node_t *node) {
    if (!queue || !node)
        return;

    node->next = NULL;
    node->prev = queue->tail;

    if (queue->tail) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }

    queue->tail = node;
    queue->size++;
}

static inline void sched_queue_remove_locked(list_queue_t *queue,
                                             list_node_t *node) {
    if (!queue || !node)
        return;

    if (node->prev) {
        node->prev->next = node->next;
    } else {
        queue->head = node->next;
    }

    if (node->next) {
        node->next->prev = node->prev;
    } else {
        queue->tail = node->prev;
    }

    if (queue->size)
        queue->size--;

    sched_node_reset(node);
}

static bool sched_queue_contains_locked(list_queue_t *queue,
                                        list_node_t *target) {
    size_t limit;
    list_node_t *node;

    if (!queue || !target)
        return false;

    limit = queue->size + 1;
    for (node = queue->head; node && limit--; node = node->next) {
        if (node == target)
            return true;
    }

    return false;
}

static list_node_t *
sched_entity_node_get_or_create(struct sched_entity *entity) {
    list_node_t *node = entity ? entity->node : NULL;
    if (node)
        return node;

    list_node_t *new_node = calloc(1, sizeof(list_node_t));
    if (!new_node)
        return NULL;

    new_node->data = entity;
    sched_node_reset(new_node);
    entity->node = new_node;
    return new_node;
}

static task_t *sched_pick_next_task_internal(sched_rq_t *scheduler,
                                             task_t *excluded) {
    task_t *next_task = NULL;
    size_t limit;

    raw_spin_lock(&scheduler->lock);

    struct sched_entity *entity = scheduler->curr;
    list_node_t *head = sched_queue_head(scheduler->sched_queue);

    if (__builtin_expect(!head, 0)) {
        scheduler->curr = scheduler->idle;
        next_task = scheduler->idle->task;
        goto out;
    }

    list_node_t *next_node = head;
    if (entity && entity != scheduler->idle && entity->on_rq &&
        entity->rq == scheduler && entity->node &&
        sched_queue_contains_locked(scheduler->sched_queue, entity->node)) {
        next_node = entity->node->next ? entity->node->next : head;
    }

    list_node_t *start = next_node;
    limit = scheduler->sched_queue ? scheduler->sched_queue->size + 1 : 0;
    do {
        struct sched_entity *next = next_node->data;
        if (__builtin_expect(next && next->on_rq && next->rq == scheduler, 1)) {
            task_t *candidate = next->task;
            if (candidate && candidate->state == TASK_READY &&
                candidate != excluded && !task_is_on_cpu(candidate)) {
                scheduler->curr = next;
                next_task = candidate;
                goto out;
            }
        }

        next_node = next_node->next ? next_node->next : head;
    } while (next_node != start && limit--);

    scheduler->curr = scheduler->idle;
    next_task = scheduler->idle->task;

out:
    raw_spin_unlock(&scheduler->lock);
    return next_task;
}

void add_sched_entity(task_t *task, sched_rq_t *scheduler) {
    if (__builtin_expect(!task || !scheduler || !task->sched_info, 0))
        return;

    struct sched_entity *entity = task->sched_info;
    entity->task = task;

    raw_spin_lock(&scheduler->lock);

    if (entity->on_rq) {
        if (entity->rq == scheduler &&
            sched_queue_contains_locked(scheduler->sched_queue, entity->node)) {
            raw_spin_unlock(&scheduler->lock);
            return;
        }
        if (entity->rq && entity->rq != scheduler) {
            raw_spin_unlock(&scheduler->lock);
            return;
        }
    }

    entity->on_rq = false;
    entity->rq = NULL;

    list_node_t *node = sched_entity_node_get_or_create(entity);
    if (!node) {
        raw_spin_unlock(&scheduler->lock);
        return;
    }

    sched_queue_enqueue_locked(scheduler->sched_queue, node);
    entity->on_rq = true;
    entity->rq = scheduler;

    raw_spin_unlock(&scheduler->lock);
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

    entity->on_rq = false;
    entity->rq = NULL;

    if (entity->node &&
        sched_queue_contains_locked(scheduler->sched_queue, entity->node)) {
        sched_queue_remove_locked(scheduler->sched_queue, entity->node);
    } else if (entity->node) {
        sched_node_reset(entity->node);
    }

    if (scheduler->curr == entity) {
        scheduler->curr = scheduler->idle;
    }

    raw_spin_unlock(&scheduler->lock);
}

task_t *sched_pick_next_task(sched_rq_t *scheduler) {
    return sched_pick_next_task_internal(scheduler, NULL);
}

task_t *sched_pick_next_task_excluding(sched_rq_t *scheduler,
                                       task_t *excluded) {
    return sched_pick_next_task_internal(scheduler, excluded);
}
