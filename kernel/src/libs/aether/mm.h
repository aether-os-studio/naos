#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>
#include <mm/mm_syscall.h>
#include <arch/arch.h>

static inline void dma_wmb(void) { write_barrier(); }

static inline void dma_rmb(void) { read_barrier(); }

static inline void dma_mb(void) { memory_barrier(); }

static inline void dma_sync_cpu_to_device(void *addr, size_t size) {
    dma_wmb();
    dcache_clean_range(addr, size);
}

static inline void dma_sync_device_to_cpu(void *addr, size_t size) {
    dcache_invalidate_range(addr, size);
    dma_rmb();
}

static inline void dma_sync_bidirectional(void *addr, size_t size) {
    dma_mb();
    dcache_flush_range(addr, size);
}
