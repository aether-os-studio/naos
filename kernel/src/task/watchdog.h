#pragma once

#include <libs/klibc.h>
#include <task/task_struct.h>

void sched_watchdog_init(void);
void sched_watchdog_init_cpu(uint32_t cpu_id);
void sched_watchdog_note_current(uint32_t cpu_id, task_t *task,
                                 uint64_t now_ns);
void sched_watchdog_task_switch(uint32_t cpu_id, task_t *task, uint64_t now_ns);
void sched_watchdog_note_resched(task_t *task, uint64_t now_ns);
void sched_watchdog_tick(uint32_t cpu_id, task_t *task, uint64_t now_ns);
void sched_watchdog_park_cpu(uint32_t cpu_id);
