#pragma once

#define ARCH_MAX_IRQ_NUM 1024
#define SCHED_HZ 250

#include <libs/klibc.h>
#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/irq/ptrace.h>
#include <arch/loongarch64/irq/irq.h>
#include <arch/loongarch64/mm/arch.h>
#include <arch/loongarch64/drivers/serial.h>
#include <arch/loongarch64/task/arch_context.h>
#include <arch/loongarch64/smp/smp.h>
#include <arch/loongarch64/syscall/syscall.h>
#include <arch/loongarch64/time/time.h>
#include <mm/page_table.h>

void arch_early_init();
void arch_init();
void arch_init_after_thread();
void arch_init_after_acpi_pci();
void arch_input_dev_init();

void arch_shutdown();

static inline void arch_pause() { __asm__ volatile("nop" ::: "memory"); }

static inline void arch_wait_for_interrupt() {
    __asm__ volatile("idle 0" ::: "memory");
}

size_t get_cache_line_size();

void dcache_clean_range(void *addr, size_t size);
void dcache_invalidate_range(void *addr, size_t size);
void dcache_flush_range(void *addr, size_t size);
void sync_instruction_memory_range(void *addr, size_t size);

void memory_barrier(void);
void read_barrier(void);
void write_barrier(void);

void arch_enable_user_access();
void arch_disable_user_access();
bool arch_memory_region_usable(uint64_t addr, uint64_t len);
uintptr_t arch_get_return_address(uint32_t level);
