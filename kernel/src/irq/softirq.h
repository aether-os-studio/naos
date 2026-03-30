#pragma once

#include <libs/klibc.h>

typedef enum softirq_id {
    SOFTIRQ_TIMER = 0,
    SOFTIRQ_TIMERFD = 1,
    SOFTIRQ_TASK_REAP = 2,
    SOFTIRQ_MAX = 8,
} softirq_id_t;

typedef void (*softirq_handler_t)(void);

void softirq_init(void);
void softirq_register(softirq_id_t id, softirq_handler_t handler);
bool softirq_raise(softirq_id_t id);
bool softirq_has_pending(void);
void softirq_handle_pending(void);
