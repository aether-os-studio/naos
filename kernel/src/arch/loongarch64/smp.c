#include <arch/arch.h>

uint64_t cpu_count = 0;
spinlock_t ap_startup_lock = SPIN_INIT;
