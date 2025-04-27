#pragma once

#define APIC_TIMER_INTERRUPT_VECTOR 0x20
#define PS2_KBD_INTERRUPT_VECTOR 0x21
#define PS2_MOUSE_INTERRUPT_VECTOR 0x22

void generic_interrupt_table_init();

void arch_enable_interrupt();
void arch_disable_interrupt();
