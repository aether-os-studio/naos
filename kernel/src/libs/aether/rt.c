#include <mod/dlinker.h>
#include <libs/mutex.h>

void __cxa_finalize() {}

EXPORT_SYMBOL(__cxa_finalize);

void __gmon_start__() {}

EXPORT_SYMBOL(__gmon_start__);

#include <arch/arch.h>

#if defined(__riscv__)
EXPORT_SYMBOL(hartid_to_cpuid);
#endif

EXPORT_SYMBOL(spin_init);
EXPORT_SYMBOL(spin_lock);
EXPORT_SYMBOL(spin_unlock);
EXPORT_SYMBOL(mutex_init);
EXPORT_SYMBOL(mutex_lock);
EXPORT_SYMBOL(mutex_unlock);

EXPORT_SYMBOL(check_unmapped);
EXPORT_SYMBOL(check_user_overflow);
