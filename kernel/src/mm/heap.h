#pragma once

#include <libs/klibc.h>

#define KERNEL_HEAP_START 0xffffffffc0000000
#define KERNEL_HEAP_SIZE (32 * 1024 * 1024)

void heap_init();

void *malloc(size_t size);
void *calloc(size_t num, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
