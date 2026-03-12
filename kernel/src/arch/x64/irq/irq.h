#pragma once

#include <arch/x64/io.h>

#define APIC_TIMER_INTERRUPT_VECTOR 0x20
#define ARCH_TIMER_IRQ APIC_TIMER_INTERRUPT_VECTOR
#define PS2_KBD_INTERRUPT_VECTOR 0x21
#define PS2_MOUSE_INTERRUPT_VECTOR 0x22
#define APIC_RESCHED_IPI_VECTOR 0x40
#define APIC_TLB_SHOOTDOWN_IPI_VECTOR 0x41

#define IRQ_ALLOCATE_NUM_BASE 80

void generic_interrupt_table_init_early();

void arch_enable_interrupt();

void arch_disable_interrupt();

bool arch_interrupt_enabled();
