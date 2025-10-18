#include <arch/arch.h>
#include <task/task.h>
#include <drivers/fdt/fdt.h>

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

void arch_early_init() {
    trap_init();
    csr_write(sscratch, (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE);
    fdt_init();
    smp_init();
    asm volatile("mv gp, %0" ::"r"(cpuid_to_hartid[current_cpu_id]));
    timer_init_hart(cpuid_to_hartid[current_cpu_id]);
}

void arch_init() {}

void arch_input_dev_init() {}
