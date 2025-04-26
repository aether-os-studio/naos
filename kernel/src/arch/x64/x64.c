#include <arch/x64/x64.h>

extern void sse_init();

void arch_early_init()
{
    close_interrupt;

    sse_init();
    irq_init();
    generic_interrupt_table_init();
    acpi_init();
    smp_init();
    tss_init();

    apic_timer_init();

    fsgsbase_init();
}

void arch_init()
{
    open_interrupt;
}
