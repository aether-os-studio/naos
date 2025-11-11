#pragma once

#if defined(__x86_64__)
#define KERNEL_HEAP_SIZE 64 * 1024 * 1024
#else
#define KERNEL_HEAP_SIZE 32 * 1024 * 1024
#endif
#define KERNEL_HEAP_START 0xffffffffc0000000

void heap_init();
