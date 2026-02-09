#pragma once

#include "ptrace.h"
#include "esr.h"
#include "arch/aarch64/drivers/gic.h"
#include "arch/aarch64/drivers/timer.h"

#define ARCH_TIMER_IRQ g_timer.irq_num

#define IRQ_ALLOCATE_NUM_BASE 0 // TODO

void arch_enable_interrupt();
void arch_disable_interrupt();
bool arch_interrupt_enabled();

void irq_init();

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs);

extern void setup_vectors();

extern uint64_t nano_time();
