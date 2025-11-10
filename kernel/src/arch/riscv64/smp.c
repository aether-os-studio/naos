#include <arch/arch.h>
#include <boot/boot.h>
#include <arch/riscv64/irq/irq.h>
#include <task/task.h>

spinlock_t ap_startup_lock = SPIN_INIT;

uint64_t cpu_count = 0;

extern bool task_initialized;

void cpu_init() {
    // SUM
    csr_set(sstatus, (1UL << 18));
    // FPU
    csr_set(sstatus, (3UL << 13));
}

atomic_t started_cpu_count = {0};

void general_ap_entry(uint64_t hartid) {
    atomic_inc(&started_cpu_count);

    trap_init();

    cpu_init();

    uint64_t sp;
    asm volatile("mv %0, sp" : "=r"(sp));
    sp &= ~(STACK_SIZE - 1);
    csr_write(sscratch, sp + STACK_SIZE);

    asm volatile("mv gp, %0" : : "r"(hartid));

    ap_startup_lock.lock = 0;

    while (!task_initialized) {
        arch_pause();
    }

    arch_set_current(idle_tasks[hartid_to_cpuid(hartid)]);

    arch_enable_interrupt();

    timer_init_hart(hartid);

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

void ap_entry(struct limine_mp_info *info) { general_ap_entry(info->hartid); }

void sbi_ap_entry(uint64_t hartid) { general_ap_entry(hartid); }

uint64_t cpuid_to_hartid[MAX_CPU_NUM] = {0};

uint64_t hartid_to_cpuid(uint64_t hartid) {
    for (uint64_t cpu_id = 0; cpu_id < cpu_count; cpu_id++) {
        if (cpuid_to_hartid[cpu_id] == hartid) {
            return cpu_id;
        }
    }

    printk("Cannot get cpu id, hartid = %d\n", hartid);

    return 0;
}

uint64_t get_current_cpu_id() {
    if (task_initialized && current_task) {
        return current_task->cpu_id;
    } else {
        uint64_t hartid = 0;
        asm volatile("mv %0, gp" : "=r"(hartid));
        return hartid_to_cpuid(hartid);
    }
}

void smp_init() {
#ifdef OPENSBI
    boot_smp_init((uintptr_t)sbi_ap_entry);
#else
    boot_smp_init((uintptr_t)ap_entry);
#endif
}
