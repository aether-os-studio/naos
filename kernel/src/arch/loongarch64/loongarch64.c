#include "arch/arch.h"

void arch_early_init() { trap_init(); }

void arch_init() {}

void arch_init_after_thread() {}

void arch_input_dev_init() {}
