#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <task/task.h>
#include <boot/boot.h>

uint64_t cpu_count = 0;

extern void ap_entry(struct limine_mp_info *cpu);

uint64_t cpuid_to_mpidr[MAX_CPU_NUM];

uint64_t current_mpidr() {
    uint64_t mpidr;
    asm volatile("mrs %0, mpidr_el1" // 读取MPIDR_EL1寄存器
                 : "=r"(mpidr));
    return mpidr & 0xFF;
}

uint64_t get_cpuid_by_mpidr(uint64_t mpidr) {
    for (uint64_t i = 0; i < cpu_count; i++)
        if (cpuid_to_mpidr[i] == mpidr)
            return i;

    printk("Cannot get cpu id, mpidr = %d\n", mpidr);

    return 0;
}

void ap_kmain(struct limine_mp_info *cpu);

extern void ap_entry();

void smp_init() {
    memset(cpuid_to_mpidr, 0, sizeof(cpuid_to_mpidr));

    boot_smp_init((uintptr_t)ap_entry);
}

spinlock_t ap_startup_lock = SPIN_INIT;

extern bool task_initialized;

extern struct global_timer_state g_timer;

void ap_kmain(struct limine_mp_info *cpu) {
    arch_disable_interrupt();

    uint64_t kpgtable_phys = (uint64_t)virt_to_phys(get_kernel_page_dir());

    asm volatile("msr TTBR1_EL1, %0" : : "r"(kpgtable_phys) : "memory");
    asm volatile("dsb ishst\n\t"
                 "tlbi vmalle1is\n\t"
                 "dsb ish\n\t"
                 "isb\n\t");

    setup_vectors();

    spin_unlock(&ap_startup_lock);

    while (!task_initialized) {
        asm volatile("nop");
    }

    arch_set_current(idle_tasks[current_cpu_id]);

    gic_init_percpu();

    while (!g_timer.initialized) {
        asm volatile("nop");
    }

    timer_init_percpu();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
