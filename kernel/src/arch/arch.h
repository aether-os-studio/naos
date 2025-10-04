#pragma once

#if defined(__x86_64__)
#include <arch/x64/x64.h>
#elif defined(__aarch64__)
#include <arch/aarch64/aarch64.h>
#elif defined(__riscv__)
#include <arch/riscv64/riscv64.h>
#elif defined(__loongarch64)
#include <arch/loongarch64/loongarch64.h>
#endif

#include <libs/elf.h>

extern uint64_t cpu_count;

extern void fast_copy_16(void *dst, const void *src, size_t size);
