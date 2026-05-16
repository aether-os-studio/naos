#pragma once

#if defined(__x86_64__)
#include <arch/x86_64/irq/ptrace.h>
#define ARCH_UTS_MACHINE "x86_64"
#define ARCH_MINSIGSTKSZ 2048
#define ARCH_SIGSTKSZ 8192
#elif defined(__aarch64__)
#include <arch/aarch64/irq/ptrace.h>
#define ARCH_UTS_MACHINE "aarch64"
#define ARCH_MINSIGSTKSZ 5120
#define ARCH_SIGSTKSZ 16384
#elif defined(__riscv__)
#include <arch/riscv64/irq/ptrace.h>
#define ARCH_UTS_MACHINE "riscv64"
#define ARCH_MINSIGSTKSZ 2048
#define ARCH_SIGSTKSZ 8192
#elif defined(__loongarch64__)
#include <arch/loongarch64/irq/ptrace.h>
#define ARCH_UTS_MACHINE "loongarch64"
#define ARCH_MINSIGSTKSZ 2048
#define ARCH_SIGSTKSZ 8192
#else
#define ARCH_UTS_MACHINE "unknown"
#define ARCH_MINSIGSTKSZ 2048
#define ARCH_SIGSTKSZ 8192
#endif
