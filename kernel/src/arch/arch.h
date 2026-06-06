#pragma once

#if defined(__x86_64__)
#include <arch/x86_64/x86_64.h>
#elif defined(__aarch64__)
#include <arch/aarch64/aarch64.h>
#elif defined(__riscv__)
#include <arch/riscv64/riscv64.h>
#elif defined(__loongarch64__)
#include <arch/loongarch64/loongarch64.h>
#endif

#include <libs/elf.h>

extern uint64_t cpu_count;

extern void fast_copy_16(void *dst, const void *src, size_t size);
void arch_program_timer_deadline_local(uint64_t deadline_ns);
