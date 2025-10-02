#pragma once

#include <libs/klibc.h>

#define ARCH_TIMER_IRQ 0 // TODO

#define IRQ_ALLOCATE_NUM_BASE 0 // TODO

void arch_enable_interrupt();
void arch_disable_interrupt();

int trap_init(void);
