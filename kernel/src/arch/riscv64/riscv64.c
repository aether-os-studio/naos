#include <arch/arch.h>
#include <drivers/fdt/fdt.h>

void arch_early_init() {
    trap_init();
    fdt_init();
    acpi_init();
    smp_init();
    timer_init_hart(get_hartid());
}

void arch_init() {}

void arch_input_dev_init() {}
