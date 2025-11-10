#include <arch/x64/x64.h>

extern void sse_init();

void arch_early_init() {
    close_interrupt;

    init_serial();

    sse_init();
    irq_init();
    generic_interrupt_table_init();
    hpet_init();
    apic_init();
    tss_init();

    apic_timer_init();
    local_apic_init();

    smp_init();

    fsgsbase_init();
}

void arch_init() {
    syscall_init();

    syscall_handler_init();

    open_interrupt;
}

void arch_input_dev_init() {
    if (ps2_init()) {
        ps2_keyboard_init();
        ps2_mouse_init();
    }
}
