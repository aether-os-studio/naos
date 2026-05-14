#include <arch/arch.h>
#include <boot/boot.h>

#define RISCV_SSTATUS_SUM (1UL << 18)

void fast_copy_16(void *dst, const void *src, size_t size) {
    memcpy(dst, src, size);
}

void arch_early_init() {
    smp_init();
    int bsp_hartid = boot_get_bsp_hartid();
    riscv64_cpu_local_init(get_cpuid_by_hartid(bsp_hartid), bsp_hartid);
    irq_init();
    init_serial();
}

void arch_init() {
    timer_init();
    timer_init_percpu();
    syscall_handler_init();
}

void arch_init_after_thread() {}

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {}

void arch_pause() { asm volatile("nop" ::: "memory"); }

void arch_wait_for_interrupt() { asm volatile("wfi" ::: "memory"); }

size_t get_cache_line_size() { return 64; }

void dcache_clean_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void dcache_invalidate_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void dcache_flush_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void sync_instruction_memory_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence.i" ::: "memory");
}

void memory_barrier(void) { asm volatile("fence rw, rw" ::: "memory"); }

void read_barrier(void) { asm volatile("fence ir, ir" ::: "memory"); }

void write_barrier(void) { asm volatile("fence ow, ow" ::: "memory"); }

void arch_enable_user_access(void) {
    uint64_t sum = RISCV_SSTATUS_SUM;
    asm volatile("csrs sstatus, %0" : : "r"(sum) : "memory");
}

void arch_disable_user_access(void) {
    uint64_t sum = RISCV_SSTATUS_SUM;
    asm volatile("csrc sstatus, %0" : : "r"(sum) : "memory");
}
