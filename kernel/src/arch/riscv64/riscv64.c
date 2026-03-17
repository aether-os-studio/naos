#include <arch/arch.h>
#include <task/task.h>
#include <drivers/fdt/fdt.h>
#include <libs/keys.h>

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

extern void cpu_init();

void arch_early_init() {
    arch_set_current(NULL);

    init_serial();
    fw_cfg_init();
    ramfb_init();
    trap_init();
    cpu_init();
    csr_write(sscratch, 0);
    smp_init();
}

void arch_init() {
    syscall_handler_init();
    timer_init_hart(cpuid_to_hartid[current_cpu_id]);
}

void arch_init_after_thread() {}

void arch_input_dev_init() {}
