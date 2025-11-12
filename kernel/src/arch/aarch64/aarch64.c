#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <arch/aarch64/acpi/gic.h>

extern void gic_init();

void arch_early_init() {
    setup_vectors();
    init_serial();
    smp_init();
    gic_init();
    gic_v3_init();
}

extern task_t *idle_tasks[MAX_CPU_NUM];

extern void syscall_handlers_init();

void arch_init() {
    arch_set_current(idle_tasks[current_cpu_id]);

    syscall_handlers_init();

    irq_init();

    arch_enable_interrupt();
}

void arch_input_dev_init() {}
