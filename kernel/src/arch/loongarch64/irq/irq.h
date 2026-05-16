#pragma once

#include <libs/klibc.h>

#define ARCH_TIMER_IRQ global_timer.irq_num
#define IRQ_ALLOCATE_NUM_BASE 64

void arch_enable_interrupt();
void arch_disable_interrupt();
bool arch_interrupt_enabled();

void irq_init();
