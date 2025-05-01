#include <arch/arch.h>
#include <interrupt/irq_manager.h>
#include <drivers/dtb/dtb.h>

void arch_early_init()
{
    setup_vectors();
    smp_init();
    acpi_init();
    dtb_init();
    irq_init();
}

void arch_init()
{
    arch_enable_interrupt();
}

void arch_input_dev_init()
{
}
