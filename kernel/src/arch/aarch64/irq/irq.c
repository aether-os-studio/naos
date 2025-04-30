#include "irq.h"

void arch_enable_interrupt()
{
    asm volatile("msr daifclr, #2");
}

void arch_disable_interrupt()
{
    asm volatile("msr daifset, #2");
}
