#include <arch/x64/x64.h>

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
    apic_ipi_init();
    local_apic_init();

    smp_init();

    fsgsbase_init();
}

void arch_init() {
    syscall_init();

    syscall_handler_init();
}

void arch_init_after_thread() {}

void arch_input_dev_init() {
    if (ps2_init()) {
        ps2_keyboard_init();
        ps2_mouse_init();
    }
}
