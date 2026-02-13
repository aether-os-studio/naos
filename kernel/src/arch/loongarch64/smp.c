#include <arch/arch.h>
#include <boot/boot.h>

uint64_t cpu_count = 0;
spinlock_t ap_startup_lock = SPIN_INIT;

extern void _ap_start(void);

uint64_t cpuid_to_physid[MAX_CPU_NUM];

void smp_init(void) { boot_smp_init((uintptr_t)_ap_start); }

void ap_kmain() {
    spin_unlock(&ap_startup_lock);

    while (1) {
        arch_pause();
    }
}
