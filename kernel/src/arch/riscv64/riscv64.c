#include <arch/arch.h>

void arch_early_init() {
    trap_init();
    acpi_init();
    smp_init();
}

void arch_init() {}

void arch_input_dev_init() {}
