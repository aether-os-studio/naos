#pragma once

#include <libs/klibc.h>

struct task;
typedef struct task task_t;

typedef struct wait_node {
    task_t *task;
    struct wait_node *next;
} wait_node_t;

typedef struct {
    spinlock_t guard;       // 保护 mutex 元数据（多核安全）
    volatile bool locked;   // 是否已锁定
    task_t *owner;          // 持有锁的任务
    uint32_t recursion;     // 递归持有层数
    wait_node_t *wait_head; // 等待队列头
    wait_node_t *wait_tail; // 等待队列尾
} mutex_t;

static void wait_queue_enqueue(mutex_t *mtx, wait_node_t *node) {
    node->next = NULL;
    if (mtx->wait_tail) {
        mtx->wait_tail->next = node;
    } else {
        mtx->wait_head = node;
    }
    mtx->wait_tail = node;
}

static wait_node_t *wait_queue_dequeue(mutex_t *mtx) {
    if (!mtx->wait_head)
        return NULL;

    wait_node_t *node = mtx->wait_head;
    mtx->wait_head = node->next;
    if (!mtx->wait_head)
        mtx->wait_tail = NULL;

    return node;
}

void mutex_init(mutex_t *mtx);

void mutex_lock(mutex_t *mtx);

bool mutex_trylock(mutex_t *mtx);

void mutex_unlock(mutex_t *mtx);
