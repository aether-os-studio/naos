#pragma once

#include <libs/klibc.h>
#include <arch/loongarch64/cpu_local.h>

extern uint64_t cpu_count;
extern uint64_t cpuid_to_physid[MAX_CPU_NUM];

void smp_init();
uint64_t get_cpuid_by_physid(uint64_t physid);

#define current_cpu_id loongarch64_current_cpu_id()
