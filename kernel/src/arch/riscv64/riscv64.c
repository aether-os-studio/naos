#include <arch/arch.h>
#include <task/task.h>
#include <drivers/fdt/fdt.h>

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

extern void cpu_init();

void arch_early_init() {
    init_serial();
    trap_init();
    cpu_init();
    uint64_t current_stack;
    asm volatile("mv %0, sp" : "=r"(current_stack));
    current_stack &= ~(STACK_SIZE - 1);
    csr_write(sscratch, current_stack + STACK_SIZE);
    fdt_init();
    smp_init();
}

void arch_init() {
    syscall_handler_init();
    arch_enable_interrupt();
    timer_init_hart(cpuid_to_hartid[current_cpu_id]);
}

void arch_input_dev_init() {}
