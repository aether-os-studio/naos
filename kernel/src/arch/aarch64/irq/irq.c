#include "irq.h"
#include <irq/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>

void arch_enable_interrupt() { asm volatile("msr daifclr, #3"); }

void arch_disable_interrupt() { asm volatile("msr daifset, #3"); }

void irq_init() {
    gic_v3_init();
    timer_init_percpu(current_cpu_id);
    irq_regist_irq(TIMER_IRQ, timer_handler, 0, NULL, &gic_controller,
                   "GENERIC TIMER", 0);
}

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

void aarch64_do_irq(struct pt_regs *regs) {
    uint64_t irq = gic_v3_get_current_irq();

    if (irq == 1023)
        return;

    do_irq(regs, irq);
}

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs) {
    sched_check_wakeup();
    uint64_t ctrl;
    asm volatile("mrs %0, cntp_ctl_el0" : "=r"(ctrl));
    asm volatile(
        "msr cntp_ctl_el0, %0" ::"r"(ctrl | (1 << 2))); // 清除ISTATUS位
}
