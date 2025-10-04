#pragma once

#include <libs/klibc.h>
#include <arch/riscv64/irq/ptrace.h>
#include <task/task_struct.h>

extern bool task_initialized;

extern uint64_t hartid_to_cpuid(uint64_t hartid);

static inline uint64_t get_current_cpu_id() {
    if (!task_initialized) {
        uint64_t hartid = 0;
        asm volatile("mv %0, tp" : "=r"(hartid));
        return hartid_to_cpuid(hartid);
    } else {
        task_t *task = NULL;
        asm volatile("mv %0, tp" : "=r"(task));
        return task->cpu_id;
    }
}

#define current_cpu_id get_current_cpu_id()

void smp_init();
