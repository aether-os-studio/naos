#include "irq.h"
#include <irq/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/signal.h>

static inline bool aarch64_user_mode_frame(const struct pt_regs *regs) {
    return regs && ((regs->cpsr & 0xF) == 0);
}

static void aarch64_handle_signal_on_user_return(struct pt_regs *regs) {
    if (aarch64_user_mode_frame(regs) && current_task && current_task->signal &&
        current_task->signal->signal) {
        task_signal(regs);
    }
}

void arch_enable_interrupt() {
    asm volatile("msr daifclr, #3\n\t"
                 "isb"
                 :
                 :
                 : "memory");
}

void arch_disable_interrupt() {
    asm volatile("msr daifset, #3\n\t"
                 "isb"
                 :
                 :
                 : "memory");
}

bool arch_interrupt_enabled() {
    long daif;
    asm volatile("mrs %0, daif\n\t" : "=r"(daif) : : "memory");
    return (daif & (1 << 1));
}

extern struct global_timer_state global_timer;

void irq_init() {
    if (timer_init()) {
        printk("timer init failure!!!\n");
    }
    printk("timer initialized with irq %d\n", global_timer.irq_num);
}

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

void aarch64_do_irq(struct pt_regs *regs) {
    uint64_t irq = gic_get_current_irq();

    if (irq == 1022 || irq == 1023)
        return;

    do_irq(regs, irq);
    aarch64_handle_signal_on_user_return(regs);
}
