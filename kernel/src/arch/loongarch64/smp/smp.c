#include <limine.h>
#include <arch/arch.h>
#include <boot/boot.h>
#include <mm/mm.h>
#include <task/task.h>

uint64_t cpu_count = 0;
uint64_t cpuid_to_physid[MAX_CPU_NUM];
spinlock_t ap_startup_lock = SPIN_INIT;

static uint64_t current_physid(void) { return csr_read(LOONGARCH_CSR_CPUID); }

uint64_t get_cpuid_by_physid(uint64_t physid) {
    for (uint64_t i = 0; i < cpu_count; i++) {
        if (cpuid_to_physid[i] == physid)
            return i;
    }
    return 0;
}

extern bool task_initialized;

void loongarch64_ap_entry(uint64_t physid);

void limine_loongarch64_ap_stub(struct limine_mp_info *mp_info) {
    loongarch64_ap_entry(mp_info->phys_id);
}

void smp_init() {
#ifdef CONFIG_BOOT_LABOOT
    boot_smp_init((uintptr_t)loongarch64_ap_entry);
#endif
#ifdef CONFIG_BOOT_LIMINE
    boot_smp_init((uintptr_t)limine_loongarch64_ap_stub);
#endif
}

void loongarch64_ap_entry(uint64_t physid) {
    arch_disable_interrupt();

    uint32_t cpu_id = (uint32_t)get_cpuid_by_physid(physid);
    loongarch64_cpu_local_init(cpu_id);

    raw_spin_unlock(&ap_startup_lock);

    irq_init();

    while (!__atomic_load_n(&task_initialized, __ATOMIC_ACQUIRE)) {
        arch_pause();
    }

    arch_set_current(idle_tasks[cpu_id]);
    task_mark_on_cpu(idle_tasks[cpu_id], true);
    task_mm_mark_cpu_active(idle_tasks[cpu_id]->mm, cpu_id);

    while (!__atomic_load_n(&global_timer.initialized, __ATOMIC_ACQUIRE)) {
        arch_pause();
    }

    timer_init_percpu();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
