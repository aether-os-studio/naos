#pragma once

#define KERNEL_HEAP_START 0xffffffffc0000000
#define KERNEL_HEAP_SIZE 64 * 1024 * 1024

void heap_init();
