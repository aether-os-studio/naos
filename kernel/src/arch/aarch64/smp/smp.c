#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <task/task.h>
#include <boot/boot.h>

uint64_t cpu_count = 0;

extern void ap_entry(struct limine_mp_info *cpu);

uint64_t cpuid_to_mpidr[MAX_CPU_NUM];

static inline uint64_t mpidr_affinity(uint64_t mpidr) {
    return (mpidr & 0xFF) | (((mpidr >> 8) & 0xFF) << 8) |
           (((mpidr >> 16) & 0xFF) << 16) | (((mpidr >> 32) & 0xFF) << 24);
}

uint64_t current_mpidr() {
    uint64_t mpidr;
    asm volatile("mrs %0, mpidr_el1" // 读取MPIDR_EL1寄存器
                 : "=r"(mpidr));
    return mpidr;
}

uint64_t get_cpuid_by_mpidr(uint64_t mpidr) {
    uint64_t affinity = mpidr_affinity(mpidr);

    for (uint64_t i = 0; i < cpu_count; i++)
        if (mpidr_affinity(cpuid_to_mpidr[i]) == affinity)
            return i;

    return 0;
}

extern void ap_entry();

void smp_init() {
    memset(cpuid_to_mpidr, 0, sizeof(cpuid_to_mpidr));

    boot_smp_init((uintptr_t)ap_entry);
}

spinlock_t ap_startup_lock = SPIN_INIT;

extern bool task_initialized;

extern struct global_timer_state global_timer;

void ap_kmain(struct limine_mp_info *cpu) {
    arch_disable_interrupt();

    uint64_t kpgtable_phys = (uint64_t)virt_to_phys(get_kernel_page_dir());

    asm volatile("msr TTBR1_EL1, %0" : : "r"(kpgtable_phys) : "memory");
    arch_flush_tlb_all();

    setup_vectors();

    spin_unlock(&ap_startup_lock);

    aarch64_cpu_local_init(get_cpuid_by_mpidr(current_mpidr()),
                           current_mpidr());

    while (!task_initialized) {
        asm volatile("nop");
    }

    while (!global_timer.initialized) {
        asm volatile("nop");
    }

    arch_set_current(idle_tasks[current_cpu_id]);
    task_mark_on_cpu(idle_tasks[current_cpu_id], true);

    gic_init_percpu();

    timer_init_percpu();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
