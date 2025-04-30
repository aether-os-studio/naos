#include <arch/arch.h>
#include <drivers/dtb/dtb.h>

void arch_early_init()
{
    arch_disable_interrupt();

    setup_vectors();
    acpi_init();
    dtb_init();
    irq_init();
    smp_init();
}

void arch_init()
{
}

void arch_input_dev_init()
{
}
