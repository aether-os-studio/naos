#include <arch/arch.h>

void dcache_clean_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

void dcache_invalidate_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

void dcache_flush_range(void *addr, size_t size) {
    __asm__ volatile("" : : : "memory");
}

void sync_instruction_memory_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    __asm__ volatile("" : : : "memory");
}

void memory_barrier(void) { __asm__ volatile("mfence" : : : "memory"); }

void read_barrier(void) { __asm__ volatile("lfence" : : : "memory"); }

void write_barrier(void) { __asm__ volatile("sfence" : : : "memory"); }
