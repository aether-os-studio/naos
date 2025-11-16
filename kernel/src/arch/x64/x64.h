#pragma once

#define ARCH_MAX_IRQ_NUM 256

#include "arch/x64/asm.h"
#include "arch/x64/acpi/normal.h"
#include "arch/x64/mm/arch.h"
#include "arch/x64/irq/ptrace.h"
#include "arch/x64/irq/gate.h"
#include "arch/x64/irq/trap.h"
#include "arch/x64/irq/irq.h"
#include "arch/x64/drivers/serial.h"
#include "arch/x64/drivers/apic_timer.h"
#include "arch/x64/drivers/chars/ps2.h"
#include "arch/x64/drivers/msi_arch.h"
#include "arch/x64/task/arch_context.h"
#include "arch/x64/task/fsgsbase.h"
#include "arch/x64/syscall/nr.h"
#include "arch/x64/syscall/syscall.h"
#include "arch/x64/syscall/cpu_info.h"
#include "arch/x64/time/time.h"

void arch_early_init();
void arch_init();
void arch_init_after_thread();
void arch_input_dev_init();

static inline void arch_pause() { asm volatile("pause"); }

static inline void arch_wait_for_interrupt() { asm volatile("hlt"); }

static inline void dcache_clean_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void dcache_invalidate_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void dcache_flush_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void memory_barrier(void) {
    __asm__ volatile("mfence" : : : "memory");
}

static inline void read_barrier(void) {
    __asm__ volatile("lfence" : : : "memory");
}

static inline void write_barrier(void) {
    __asm__ volatile("sfence" : : : "memory");
}
