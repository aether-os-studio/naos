
#if defined(__x86_64__)
#include <arch/x64/x64.h>
#elif defined(__aarch64__)
#include <arch/aarch64/aarch64.h>
#elif defined(__riscv)
#include <arch/riscv64/riscv64.h>
#elif defined(__loongarch64)
#include <arch/loongarch64/loongarch64.h>
#endif