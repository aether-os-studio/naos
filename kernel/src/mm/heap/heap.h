#pragma once

#define KERNEL_HEAP_SIZE 512 * 1024 * 1024
#define KERNEL_HEAP_START 0xffffffffc0000000

void heap_init();
