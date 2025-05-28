#pragma once

#include "ptrace.h"
#include "esr.h"
#include "arch/aarch64/drivers/gic.h"

#define ARCH_TIMER_IRQ TIMER_IRQ

void arch_enable_interrupt();
void arch_disable_interrupt();

void irq_init();

extern uint64_t get_current_irq();

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs);

extern void timer_init_percpu();

extern void setup_vectors();
