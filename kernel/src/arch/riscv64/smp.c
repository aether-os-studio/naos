#include <arch/arch.h>
#include <boot/boot.h>
#include <arch/riscv64/irq/irq.h>
#include <task/task.h>

spinlock_t ap_startup_lock = {0};

uint64_t cpu_count;

extern bool task_initialized;

void sum_init() { csr_set(sstatus, (1UL << 18)); }

void ap_entry(struct limine_mp_info *cpu) {
    asm volatile("mv gp, %0" : : "r"(cpu->hartid));

    trap_init();

    sum_init();
    csr_write(sscratch, (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE);

    printk("cpu %d starting...\n", current_cpu_id);

    timer_init_hart(cpu->hartid);

    ap_startup_lock.lock = 0;

    while (!task_initialized) {
        arch_pause();
    }

    arch_set_current(idle_tasks[current_cpu_id]);

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

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

void smp_init() { boot_smp_init((uintptr_t)ap_entry); }
