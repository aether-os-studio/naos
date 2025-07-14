#pragma once

#define ALIGNED_BASE 0x1000

#include "mm/alloc/alloc.h"
#include "libs/klibc.h"

#define KERNEL_HEAP_START 0xffffffc000000000
#define KERNEL_HEAP_SIZE 512 * 1024 * 1024

uint64_t get_all_memusage();
void heap_init();
