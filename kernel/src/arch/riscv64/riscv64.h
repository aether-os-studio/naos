#pragma once

#define ARCH_MAX_IRQ_NUM 1020

#include "arch/riscv64/io.h"
#include "arch/riscv64/sbi.h"
#include "arch/riscv64/drivers/fw_cfg.h"
#include "arch/riscv64/drivers/ramfb.h"
#include "arch/riscv64/drivers/timer.h"
#include "arch/riscv64/drivers/serial.h"
#include "arch/riscv64/drivers/ns16550.h"
#include "arch/riscv64/drivers/char/kb.h"
#include "arch/riscv64/irq/ptrace.h"
#include "arch/riscv64/irq/irq.h"
#include "arch/riscv64/mm/arch.h"
#include "arch/riscv64/task/arch_context.h"
#include "arch/riscv64/syscall/nr.h"
#include "arch/riscv64/syscall/syscall.h"
#include "arch/riscv64/time/time.h"
#include "arch/riscv64/smp.h"

void arch_early_init();
void arch_init();
void arch_init_after_thread();
void arch_input_dev_init();

static inline void arch_pause() { asm volatile("nop"); }

static inline void arch_wait_for_interrupt() { asm volatile("wfi"); }

static inline void dcache_clean_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void dcache_invalidate_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void dcache_flush_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

static inline void memory_barrier(void) { __asm__ volatile("" : : : "memory"); }

static inline void read_barrier(void) { __asm__ volatile("" : : : "memory"); }

static inline void write_barrier(void) { __asm__ volatile("" : : : "memory"); }
