#pragma once

#define ALIGNED_BASE 0x1000

#define KERNEL_HEAP_START 0xffffc00000000000
#define KERNEL_HEAP_SIZE (32 * 1024 * 1024)

#include "mm/heap/alloc.h"
#include <libs/klibc.h>

uint64_t get_all_memusage();
void heap_init();
