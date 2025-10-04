#include <arch/arch.h>
#include <boot/boot.h>
#include <arch/riscv64/irq/irq.h>
#include <task/task.h>

spinlock_t ap_startup_lock = {0};

uint64_t cpu_count;

void ap_entry(struct limine_mp_info *cpu) {
    task_t *fake_task = malloc(sizeof(task_t));
    fake_task->cpu_id = hartid_to_cpuid(cpu->hartid);
    asm volatile("mv tp, %0" : : "r"(fake_task));

    trap_init();

    printk("cpu %d starting...\n", current_cpu_id);

    timer_init_hart(cpu->hartid);

    spin_unlock(&ap_startup_lock);

    while (1)
        arch_pause();
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
