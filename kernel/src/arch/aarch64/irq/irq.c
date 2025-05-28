#include "irq.h"
#include <interrupt/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>

void arch_enable_interrupt()
{
    asm volatile("msr daifclr, #3");
}

void arch_disable_interrupt()
{
    asm volatile("msr daifset, #3");
}

void irq_init()
{
    gic_init();
    timer_init_percpu();
    irq_regist_irq(TIMER_IRQ, timer_handler, 0, NULL, &gic_controller, "GENERIC TIMER");
}

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

void aarch64_do_irq(struct pt_regs *regs)
{
    uint64_t irq = get_current_irq();

    if (irq == 1023)
        return;

    do_irq(regs, irq);
}

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs)
{
    current_task->jiffies++;

    uint64_t ctrl;
    asm volatile("mrs %0, cntp_ctl_el0" : "=r"(ctrl));
    asm volatile("msr cntp_ctl_el0, %0" ::"r"(ctrl | (1 << 2))); // 清除ISTATUS位
}
