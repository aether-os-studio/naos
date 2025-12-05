#pragma once

#include <libs/klibc.h>
#include <libs/llist.h>
#include <mm/mm.h>

struct slab {
    struct llist_header list;
    uintptr_t page;

    size_t using_count;
    size_t free_count;

    void *v_address;

    size_t color_length;
    size_t color_count;

    size_t *color_map;
};

struct slab_cache {
    size_t size;
    size_t total_using;
    size_t total_free;
    struct slab *cache_pool;
    struct slab *cache_dma_pool;
    void *(*constructor)(void *v_address, size_t arg);
    void *(*destructor)(void *v_address, size_t arg);
};

extern struct slab_cache kmalloc_cache_size[16];

#define SIZEOF_LONG_ALIGN(size)                                                \
    ((size + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define SIZEOF_INT_ALIGN(size) ((size + sizeof(int) - 1) & ~(sizeof(int) - 1))

void slab_init();
