#pragma once

#include <libs/klibc.h>
#include <arch/riscv64/irq/ptrace.h>
#include <task/task_struct.h>

extern bool task_initialized;

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

extern uint64_t hartid_to_cpuid(uint64_t hartid);

uint64_t get_current_cpu_id();

#define current_cpu_id get_current_cpu_id()

void smp_init();
