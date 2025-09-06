#include "mm/heap/heap.h"
#include "mm/heap/alloc/area.h"
#include "mm/mm.h"
#include <libs/klibc.h>

static struct mpool pool;

static spinlock_t malloc_lock = {0};

uint64_t get_all_memusage()
{
    return KERNEL_HEAP_SIZE;
}

static void alloc_enter()
{
    spin_lock(&malloc_lock);
}

static void alloc_exit()
{
    spin_unlock(&malloc_lock);
}

void *malloc(size_t size)
{
    alloc_enter();
    void *ptr = mpool_alloc(&pool, size);
    alloc_exit();
    return ptr;
}

void free(void *ptr)
{
    alloc_enter();
    mpool_free(&pool, ptr);
    alloc_exit();
}

void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    return ptr;
}

void *calloc(size_t n, size_t size)
{
    if (__builtin_mul_overflow(n, size, &size))
        return NULL;
    void *ptr = malloc(size);
    if (ptr == NULL)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}

void *realloc(void *ptr, size_t newsize)
{
    alloc_enter();
    void *n_ptr = mpool_realloc(&pool, ptr, newsize);
    alloc_exit();
    return n_ptr;
}

void *reallocarray(void *ptr, size_t n, size_t size)
{
    return realloc(ptr, n * size);
}

void *aligned_alloc(size_t align, size_t size)
{
    alloc_enter();
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    alloc_exit();
    return ptr;
}

size_t malloc_usable_size(void *ptr)
{
    alloc_enter();
    size_t size = mpool_msize(&pool, ptr);
    alloc_exit();
    return size;
}

void *memalign(size_t align, size_t size)
{
    alloc_enter();
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    alloc_exit();
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    alloc_enter();
    void *ptr = mpool_aligned_alloc(&pool, size, alignment);
    alloc_exit();
    if (ptr == NULL)
        return 1;
    *memptr = ptr;
    return 0;
}

void *valloc(size_t size)
{
    alloc_enter();
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    alloc_exit();
    return ptr;
}

void *pvalloc(size_t size)
{
    alloc_enter();
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    alloc_exit();
    return ptr;
}

void heap_init()
{
    mpool_init(&pool, alloc_frames_bytes(KERNEL_HEAP_SIZE), KERNEL_HEAP_SIZE);
}
