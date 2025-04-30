#include "irq.h"

void arch_enable_interrupt()
{
    asm volatile("msr daifclr, #2");
}

void arch_disable_interrupt()
{
    asm volatile("msr daifset, #2");
}

void irq_init()
{
}

void aarch64_do_irq(struct pt_regs *regs)
{
    // int irqno = gicv2_get_current_irq();
}
