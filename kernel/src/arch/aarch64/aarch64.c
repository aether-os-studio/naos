#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <boot/boot.h>
#include <drivers/fdt/fdt.h>
#include <mod/dlinker.h>

extern void gic_init();

void arch_early_init() {
    setup_vectors();
    init_serial();
    smp_init();
}

extern task_t *idle_tasks[MAX_CPU_NUM];

extern void syscall_handlers_init();

void arch_init() {
    arch_set_current(idle_tasks[current_cpu_id]);

    syscall_handlers_init();

    gic_init();

    irq_init();
}

void arch_init_after_thread() { pci_brcmstb_init(); }

void arch_input_dev_init() {}

EXPORT_SYMBOL(get_cache_line_size);
