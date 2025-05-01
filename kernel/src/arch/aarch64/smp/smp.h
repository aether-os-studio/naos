#pragma once

#include <libs/klibc.h>

extern uint64_t cpu_count;

void smp_init();
uint64_t get_cpuid_by_mpidr(uint64_t mpidr);
uint64_t current_mpidr();

#define current_cpu_id get_cpuid_by_mpidr(current_mpidr())
