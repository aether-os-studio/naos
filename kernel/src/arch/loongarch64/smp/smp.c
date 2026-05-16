#include <arch/arch.h>

uint64_t cpu_count = 1;
uint64_t cpuid_to_physid[MAX_CPU_NUM];
spinlock_t ap_startup_lock = SPIN_INIT;

void smp_init() {}
