#pragma once

#include "ptrace.h"
#include "esr.h"

void arch_enable_interrupt();
void arch_disable_interrupt();

void irq_init();

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs);

extern void setup_vectors();
