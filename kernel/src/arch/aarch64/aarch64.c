#include <arch/arch.h>
#include <boot/boot.h>
#include <drivers/fdt/fdt.h>
#include <mod/dlinker.h>
#include <task/task.h>

extern void gic_init();

void arch_early_init() {
    setup_vectors();
    init_serial();
    aarch64_cpu_local_init(get_cpuid_by_mpidr(current_mpidr()),
                           current_mpidr());
    smp_init();
}

void cpu_init() {
    asm volatile("mrs x0, sctlr_el1\n\t"
                 "orr x0, x0, #(1 << 15)\n\t"
                 "orr x0, x0, #(1 << 26)\n\t"
                 "msr sctlr_el1, x0\n\t" ::
                     : "x0");
}

extern void syscall_handler_init();

void arch_init() {
    gic_init();
    gic_ipi_init();

    irq_init();

    cpu_init();

    timer_init_percpu();

    syscall_handler_init();
}

void arch_init_after_thread() { pci_brcmstb_init(); }

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {}

void arch_program_timer_deadline_local(uint64_t deadline_ns) {
    uint64_t now = nano_time();
    uint64_t delta_ns = deadline_ns > now ? deadline_ns - now : 1;
    timer_set_sched_interval_ns(delta_ns);
}

void arch_shutdown() {
    while (1) {
        asm volatile("wfi");
    }
}

void arch_pause() { asm volatile("nop"); }

void arch_wait_for_interrupt() { asm volatile("wfi"); }

size_t get_cache_line_size() {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    size_t dminline = (ctr >> 16) & 0xF;
    return 4 << dminline;
}

static size_t get_icache_line_size() {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    size_t iminline = ctr & 0xF;
    return 4 << iminline;
}

void dcache_clean_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size)
        __asm__ volatile("dc cvac, %0" : : "r"(va) : "memory");

    __asm__ volatile("dsb sy" : : : "memory");
}

void dcache_invalidate_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size)
        __asm__ volatile("dc ivac, %0" : : "r"(va) : "memory");

    __asm__ volatile("dsb sy" : : : "memory");
}

void dcache_flush_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line_size = get_cache_line_size();

    start &= ~(line_size - 1);
    end = (end + line_size - 1) & ~(line_size - 1);

    for (uintptr_t va = start; va < end; va += line_size)
        __asm__ volatile("dc civac, %0" : : "r"(va) : "memory");

    __asm__ volatile("dsb sy" : : : "memory");
}

void sync_instruction_memory_range(void *addr, size_t size) {
    if (!addr || size == 0)
        return;

    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t dcache_line_size = get_cache_line_size();
    uintptr_t icache_line_size = get_icache_line_size();
    uintptr_t dcache_start = start & ~(dcache_line_size - 1);
    uintptr_t dcache_end =
        (end + dcache_line_size - 1) & ~(dcache_line_size - 1);
    uintptr_t icache_start = start & ~(icache_line_size - 1);
    uintptr_t icache_end =
        (end + icache_line_size - 1) & ~(icache_line_size - 1);

    for (uintptr_t va = dcache_start; va < dcache_end; va += dcache_line_size)
        __asm__ volatile("dc cvau, %0" : : "r"(va) : "memory");

    __asm__ volatile("dsb ish" : : : "memory");

    for (uintptr_t va = icache_start; va < icache_end; va += icache_line_size)
        __asm__ volatile("ic ivau, %0" : : "r"(va) : "memory");

    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("isb" : : : "memory");
}

void memory_barrier(void) { __asm__ volatile("dsb sy" : : : "memory"); }

void read_barrier(void) { __asm__ volatile("dsb ld" : : : "memory"); }

void write_barrier(void) { __asm__ volatile("dsb st" : : : "memory"); }

void arch_enable_user_access() {}
void arch_disable_user_access() {}

bool arch_memory_region_usable(uint64_t addr, uint64_t len) {
    (void)addr;
    (void)len;
    return true;
}

uintptr_t arch_get_return_address(uint32_t level) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif
#define RETURN_ADDRESS(level)                                                  \
    do {                                                                       \
        if (!__builtin_frame_address(level))                                   \
            return 0;                                                          \
        return (uintptr_t)__builtin_return_address(level);                     \
    } while (0)
    switch (level) {
    case 0:
        RETURN_ADDRESS(0);
    case 1:
        RETURN_ADDRESS(1);
    case 2:
        RETURN_ADDRESS(2);
    case 3:
        RETURN_ADDRESS(3);
    case 4:
        RETURN_ADDRESS(4);
    case 5:
        RETURN_ADDRESS(5);
    case 6:
        RETURN_ADDRESS(6);
    case 7:
        RETURN_ADDRESS(7);
    case 8:
        RETURN_ADDRESS(8);
    case 9:
        RETURN_ADDRESS(9);
    case 10:
        RETURN_ADDRESS(10);
    case 11:
        RETURN_ADDRESS(11);
    case 12:
        RETURN_ADDRESS(12);
    case 13:
        RETURN_ADDRESS(13);
    case 14:
        RETURN_ADDRESS(14);
    case 15:
        RETURN_ADDRESS(15);
    case 16:
        RETURN_ADDRESS(16);
    default:
        return 0;
    }
#undef RETURN_ADDRESS
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}
