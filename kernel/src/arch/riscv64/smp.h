#pragma once

#include <libs/klibc.h>

static inline uint64_t get_hartid() {
    uint64_t hartid;
    asm volatile("mv %0, tp" : "=r"(hartid));
    return hartid;
}

extern uint64_t hartid_to_cpuid(uint64_t hartid);

#define current_cpu_id hartid_to_cpuid(get_hartid())

void smp_init();
