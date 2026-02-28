#pragma once

#include <arch/x64/io.h>

#define APIC_TIMER_INTERRUPT_VECTOR 0x20
#define ARCH_TIMER_IRQ APIC_TIMER_INTERRUPT_VECTOR
#define PS2_KBD_INTERRUPT_VECTOR 0x21
#define PS2_MOUSE_INTERRUPT_VECTOR 0x22

#define IRQ_ALLOCATE_NUM_BASE 80

void generic_interrupt_table_init_early();

static inline void arch_enable_interrupt() { open_interrupt; }

static inline void arch_disable_interrupt() { close_interrupt; }

static inline bool arch_interrupt_enabled() {
    long flags;
    asm volatile("pushfq\n\t"
                 "pop %0\n\t"
                 : "=r"(flags)
                 :
                 : "memory");
    return !!(flags & (1 << 9));
}
