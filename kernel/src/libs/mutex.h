#pragma once

#include <task/task.h>

typedef struct wait_node {
    task_t *task;
    struct wait_node *next;
} wait_node_t;

typedef struct {
    volatile bool locked;   // 是否已锁定
    task_t *owner;          // 持有锁的任务
    uint32_t recursion;     // 递归计数（可选，支持递归锁）
    wait_node_t *wait_head; // 等待队列头
    wait_node_t *wait_tail; // 等待队列尾
} mutex_t;

static inline void mutex_init(mutex_t *mtx) {
    mtx->locked = false;
    mtx->owner = NULL;
    mtx->recursion = 0;
    mtx->wait_head = NULL;
    mtx->wait_tail = NULL;
}

static void wait_queue_enqueue(mutex_t *mtx, wait_node_t *node) {
    node->next = NULL;
    if (mtx->wait_tail) {
        mtx->wait_tail->next = node;
    } else {
        mtx->wait_head = node;
    }
    mtx->wait_tail = node;
}

static task_t *wait_queue_dequeue(mutex_t *mtx) {
    if (!mtx->wait_head)
        return NULL;

    wait_node_t *node = mtx->wait_head;
    mtx->wait_head = node->next;
    if (!mtx->wait_head)
        mtx->wait_tail = NULL;

    return node->task;
}

static inline uint32_t irq_disable(void) {
    uint32_t state = arch_interrupt_enabled();
    arch_disable_interrupt();
    return state;
}

static inline void irq_restore(uint32_t state) {
    if (state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }
}

static inline void mutex_lock(mutex_t *mtx) {
    uint32_t flags = irq_disable();

    task_t *self = current_task;

    if (mtx->locked && mtx->owner == self) {
        mtx->recursion++;
        irq_restore(flags);
        return;
    }

    if (!mtx->locked) {
        mtx->locked = true;
        mtx->owner = self;
        mtx->recursion = 1;
        irq_restore(flags);
        return;
    }

    wait_node_t node;
    node.task = self;

    wait_queue_enqueue(mtx, &node);

    task_block(self, TASK_BLOCKING, -1);

    irq_restore(flags);

    schedule(SCHED_FLAG_YIELD);
}

static inline bool mutex_trylock(mutex_t *mtx) {
    uint32_t flags = irq_disable();

    task_t *self = current_task;

    if (mtx->locked && mtx->owner == self) {
        mtx->recursion++;
        irq_restore(flags);
        return true;
    }

    if (!mtx->locked) {
        mtx->locked = true;
        mtx->owner = self;
        mtx->recursion = 1;
        irq_restore(flags);
        return true;
    }

    irq_restore(flags);
    return false;
}

static inline void mutex_unlock(mutex_t *mtx) {
    uint32_t flags = irq_disable();

    task_t *self = current_task;

    if (mtx->owner != self) {
        irq_restore(flags);
        return;
    }

    mtx->recursion--;
    if (mtx->recursion > 0) {
        irq_restore(flags);
        return;
    }

    task_t *waiter = wait_queue_dequeue(mtx);

    if (waiter) {
        mtx->owner = waiter;
        mtx->recursion = 1;

        task_unblock(waiter, EOK);
    } else {
        mtx->locked = false;
        mtx->owner = NULL;
    }

    irq_restore(flags);

    schedule(SCHED_FLAG_YIELD);
}
