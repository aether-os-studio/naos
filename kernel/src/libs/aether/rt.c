#include <mod/dlinker.h>

void __cxa_finalize() {}

EXPORT_SYMBOL(__cxa_finalize);

void __gmon_start__() {}

EXPORT_SYMBOL(__gmon_start__);

#include <arch/arch.h>

#if defined(__riscv__)
EXPORT_SYMBOL(hartid_to_cpuid);
#endif
