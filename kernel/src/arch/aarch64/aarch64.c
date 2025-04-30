#include <arch/arch.h>

void arch_early_init()
{
    arch_disable_interrupt();

    setup_vectors();
    irq_init();
    smp_init();
}

void arch_init()
{
}

void arch_input_dev_init()
{
}
