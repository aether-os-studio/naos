#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

extern uint64_t memory_size;

extern spinlock_t tmpfs_mem_limit_lock;
extern uint64_t tmpfs_mem_used;

static inline uint64_t tmpfs_mem_align(uint64_t size) {
    if (size == 0)
        return 0;

    return PADDING_UP(size, DEFAULT_PAGE_SIZE);
}

static inline uint64_t tmpfs_mem_limit(void) {
    return PADDING_DOWN(memory_size / 2, DEFAULT_PAGE_SIZE);
}

int tmpfs_mem_resize_reserve(uint64_t old_size, uint64_t new_size);
void tmpfs_mem_release(uint64_t size);
