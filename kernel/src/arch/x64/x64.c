#include <arch/x64/x64.h>

extern void sse_init();

void NA_arch_early_init()
{
    close_interrupt;

    sse_init();
    irq_init();
    generic_interrupt_table_init();
    acpi_init();
    smp_init();
    tss_init();

    apic_timer_init();
}

void NA_arch_init()
{
    open_interrupt;
}
