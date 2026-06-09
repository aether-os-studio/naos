#pragma once

#include <libs/klibc.h>

void kmalloc_init(void);

struct mallinfo {
    size_t arena;
    size_t ordblks;
    size_t smblks;
    size_t hblks;
    size_t hblkhd;
    size_t usmblks;
    size_t fsmblks;
    size_t uordblks;
    size_t fordblks;
    size_t keepcost;
};

size_t malloc_usable_size(void *ptr);
void *memalign(size_t alignment, size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);
void *valloc(size_t size);
void *pvalloc(size_t size);
int malloc_trim(size_t pad);
int mallopt(int param, int value);
struct mallinfo mallinfo(void);
void malloc_stats(void);
