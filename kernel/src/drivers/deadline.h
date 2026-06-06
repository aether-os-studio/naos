#pragma once

#include <libs/klibc.h>
#include <libs/rbtree.h>

typedef enum deadline_source_type {
    DEADLINE_SOURCE_SCHED_TICK = 0,
    DEADLINE_SOURCE_TASK_TIMEOUT = 1,
    DEADLINE_SOURCE_TASK_SIGNAL_TIMER = 2,
    DEADLINE_SOURCE_TIMERFD_MONO = 3,
    DEADLINE_SOURCE_TIMERFD_REAL = 4,
} deadline_source_type_t;

typedef struct deadline_source {
    rb_node_t node;
    uint64_t deadline_ns;
    uint32_t cpu_id;
    deadline_source_type_t type;
    bool queued;
} deadline_source_t;

void deadline_source_init(deadline_source_t *source,
                          deadline_source_type_t type, uint32_t cpu_id);
void deadline_source_update(deadline_source_t *source, uint64_t deadline_ns);
uint64_t deadline_next_ns_for_cpu(uint32_t cpu_id);
void deadline_reprogram_cpu(uint32_t cpu_id);
void deadline_reprogram_local(void);
