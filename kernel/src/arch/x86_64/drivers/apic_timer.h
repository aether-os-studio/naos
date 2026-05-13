#pragma once

#include <libs/klibc.h>

struct pt_regs;

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs);
void apic_timer_init();
