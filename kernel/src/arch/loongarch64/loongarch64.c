#include "loongarch64.h"

void fast_copy_16(void *dst, const void *src, size_t size) {
    memcpy(dst, src, size);
}

void arch_early_init() {
    init_serial();
    loongarch64_cpu_local_init(0);
}

void arch_init() { syscall_handler_init(); }

void arch_init_after_thread() {}

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {}

void arch_shutdown() {}

size_t get_cache_line_size() { return 64; }

void dcache_clean_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void dcache_invalidate_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void dcache_flush_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void sync_instruction_memory_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void memory_barrier(void) { __sync_synchronize(); }

void read_barrier(void) { __asm__ volatile("" ::: "memory"); }

void write_barrier(void) { __asm__ volatile("" ::: "memory"); }

void arch_enable_user_access() {}

void arch_disable_user_access() {}
