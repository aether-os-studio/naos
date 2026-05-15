#include <arch/x86_64/x86_64.h>

extern void sse_init();

void arch_early_init() {
    close_interrupt;

    init_serial();

    sse_init();
    irq_init();
    generic_interrupt_table_init_early();
    hpet_init();
    apic_init();
    x64_cpu_local_init(get_cpuid_by_lapic_id((uint32_t)lapic_id()),
                       (uint32_t)lapic_id());
    tss_init();

    apic_timer_init();
    local_apic_init();

    apic_ipi_init();

    smp_init();

    fsgsbase_init();
}

void arch_init() {
    syscall_init();
    syscall_handler_init();
}

void arch_init_after_thread() {}

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {
    bool irq_state = arch_interrupt_enabled();
    if (irq_state)
        arch_disable_interrupt();

    if (ps2_init()) {
        if (!ps2_keyboard_init()) {
            printk("PS/2 keyboard init failed\n");
        }
        if (!ps2_mouse_init()) {
            printk("PS/2 mouse init failed\n");
        }
    }

    if (irq_state)
        arch_enable_interrupt();
}

void arch_shutdown() {}

void arch_enable_user_access() {}
void arch_disable_user_access() {}
