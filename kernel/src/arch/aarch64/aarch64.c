#include <arch/arch.h>
#include <interrupt/irq_manager.h>
#include <drivers/dtb/dtb.h>
#include <arch/aarch64/acpi/gic.h>

void arch_early_init()
{
    setup_vectors();
    smp_init();
    acpi_init();
    dtb_init();
    irq_init();
}

extern task_t *idle_tasks[MAX_CPU_NUM];

void arch_init()
{
    arch_set_current(idle_tasks[current_cpu_id]);

    arch_enable_interrupt();
}

void arch_input_dev_init()
{
}
