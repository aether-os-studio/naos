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
    hpet_clockevent_init();
    rtc_cmos_init();

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

void arch_shutdown() {
    while (1) {
        asm volatile("cli\n\thlt");
    }
}

void arch_enable_user_access() {}
void arch_disable_user_access() {}

void arch_program_timer_deadline_local(uint64_t deadline_ns) {
    if (deadline_ns == UINT64_MAX) {
        apic_timer_set_interval_ns(1000000000ULL / SCHED_HZ);
        return;
    }

    uint64_t now = nano_time();
    uint64_t delta_ns = deadline_ns > now ? deadline_ns - now : 1;
    apic_timer_set_interval_ns(delta_ns);
}

bool arch_memory_region_usable(uint64_t addr, uint64_t len) {
    (void)len;
    return addr >= 0x100000;
}

uintptr_t arch_get_return_address(uint32_t level) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif
    switch (level) {
    case 0:
        return (uintptr_t)__builtin_return_address(0);
    case 1:
        return (uintptr_t)__builtin_return_address(1);
    case 2:
        return (uintptr_t)__builtin_return_address(2);
    case 3:
        return (uintptr_t)__builtin_return_address(3);
    case 4:
        return (uintptr_t)__builtin_return_address(4);
    case 5:
        return (uintptr_t)__builtin_return_address(5);
    case 6:
        return (uintptr_t)__builtin_return_address(6);
    case 7:
        return (uintptr_t)__builtin_return_address(7);
    case 8:
        return (uintptr_t)__builtin_return_address(8);
    case 9:
        return (uintptr_t)__builtin_return_address(9);
    default:
        return 0;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}
