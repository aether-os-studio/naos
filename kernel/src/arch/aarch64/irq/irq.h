#pragma once

#include "ptrace.h"
#include "esr.h"

void arch_enable_interrupt();
void arch_disable_interrupt();

void irq_init();

extern void setup_vectors();
