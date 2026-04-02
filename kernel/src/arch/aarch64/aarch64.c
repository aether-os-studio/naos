#include <arch/arch.h>
#include <irq/irq_manager.h>
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

void arch_init() {
    gic_init();
    gic_ipi_init();

    irq_init();

    cpu_init();
}

void arch_init_after_thread() { pci_brcmstb_init(); }

void arch_input_dev_init() {}

void arch_pause() { asm volatile("nop"); }

void arch_wait_for_interrupt() { asm volatile("wfi"); }

size_t get_cache_line_size() {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    size_t dminline = (ctr >> 16) & 0xF;
    return 4 << dminline;
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

void memory_barrier(void) { __asm__ volatile("dsb sy" : : : "memory"); }

void read_barrier(void) { __asm__ volatile("dsb ld" : : : "memory"); }

void write_barrier(void) { __asm__ volatile("dsb st" : : : "memory"); }
