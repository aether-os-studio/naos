#pragma once

#include <libsyscall.h>

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

void *alloc_shared_memory(size_t size);
void free_shared_memory(void *ptr);

void exit(int code);
void abort();
