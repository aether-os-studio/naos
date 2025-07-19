#pragma once

#define KERNEL_HEAP_START 0xffffc00000000000
#define KERNEL_HEAP_SIZE 256 * 1024 * 1024

#include <mm/heap/alloc.h>

extern void init_heap();

static inline void heap_init()
{
    init_heap();
}
