#pragma once

#define ARCH_MAX_IRQ_NUM 1020

#include "arch/aarch64/drivers/chars/keyboard.h"
#include "arch/aarch64/drivers/chars/mouse.h"
#include "arch/aarch64/drivers/chars/serial.h"
#include "arch/aarch64/drivers/gic.h"
#include "arch/aarch64/drivers/timer.h"
#include "arch/aarch64/drivers/pci/pci-brcmstb.h"
#include "arch/aarch64/irq/ptrace.h"
#include "arch/aarch64/irq/irq.h"
#include "arch/aarch64/mm/arch.h"
#include "arch/aarch64/task/arch_context.h"
#include "arch/aarch64/smp/smp.h"
#include "arch/aarch64/syscall/nr.h"
#include "arch/aarch64/syscall/syscall.h"
#include "arch/aarch64/time/time.h"
#include "mm/page_table.h"

void arch_early_init();
void arch_init();
void arch_init_after_thread();
void arch_input_dev_init();

static inline void arch_pause() { asm volatile("nop"); }

static inline void arch_wait_for_interrupt() { asm volatile("wfi"); }

static inline size_t get_cache_line_size() {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    size_t dminline = (ctr >> 16) & 0xF;
    return 4 << dminline;
}

static inline void dcache_clean_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size) {
        __asm__ volatile("dc cvac, %0" : : "r"(va) : "memory");
    }

    __asm__ volatile("dsb sy" : : : "memory");
}

static inline void dcache_invalidate_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size) {
        __asm__ volatile("dc ivac, %0" : : "r"(va) : "memory");
    }

    __asm__ volatile("dsb sy" : : : "memory");
}

static inline void dcache_flush_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size) {
        __asm__ volatile("dc civac, %0" : : "r"(va) : "memory");
    }

    __asm__ volatile("dsb sy" : : : "memory");
}

static inline void memory_barrier(void) {
    __asm__ volatile("dsb sy" : : : "memory");
}

static inline void read_barrier(void) {
    __asm__ volatile("dsb ld" : : : "memory");
}

static inline void write_barrier(void) {
    __asm__ volatile("dsb st" : : : "memory");
}
