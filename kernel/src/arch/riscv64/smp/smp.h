#pragma once

#include <libs/klibc.h>
#include <arch/riscv64/cpu_local.h>

extern uint64_t cpu_count;
extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

void smp_init();
uint64_t get_cpuid_by_hartid(uint64_t hartid);
uint64_t current_hartid();
uint64_t riscv64_sched_ipi_irq(void);

#define current_cpu_id riscv64_current_cpu_id()
