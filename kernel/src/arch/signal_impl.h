#pragma once

#if defined(__x86_64__)
#include <arch/x86_64/task/signal_impl.h>
#elif defined(__aarch64__)
#include <arch/aarch64/task/signal_impl.h>
#elif defined(__riscv__)
#include <arch/riscv64/task/signal_impl.h>
#elif defined(__loongarch64__)
#include <arch/loongarch64/task/signal_impl.h>
#endif
