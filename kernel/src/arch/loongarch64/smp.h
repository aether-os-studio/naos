#pragma once

#include <libs/klibc.h>

#define current_cpu_id 0

extern uint64_t cpuid_to_physid[MAX_CPU_NUM];

void smp_init();
