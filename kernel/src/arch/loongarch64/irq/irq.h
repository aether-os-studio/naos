#pragma once

#include <libs/klibc.h>

#define ARCH_TIMER_IRQ 11 // TODO

#define IRQ_ALLOCATE_NUM_BASE 0 // TODO

bool arch_interrupt_enabled();
void arch_enable_interrupt();
void arch_disable_interrupt();
