#include <arch/arch.h>
#include <task/task.h>
#include <drivers/fdt/fdt.h>

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

void arch_early_init() {
    trap_init();
    uintptr_t sp;
    asm volatile("mv %0, sp" : "=r"(sp));
    csr_write(sscratch, sp & ~(STACK_SIZE - 1) + STACK_SIZE);
    fdt_init();
    acpi_init();
    smp_init();
    timer_init_hart(cpuid_to_hartid[current_cpu_id]);
}

void arch_init() {}

void arch_input_dev_init() {}
