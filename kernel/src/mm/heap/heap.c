#include "heap.h"
#include "mm/mm.h"
#include "mm/hhdm.h"

static struct mpool pool;

uint64_t get_all_memusage()
{
    return KERNEL_HEAP_SIZE;
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

void *malloc(size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_alloc(&pool, size);
    arch_enable_interrupt();
    return ptr;
}

void free(void *ptr)
{
    arch_disable_interrupt();
    mpool_free(&pool, ptr);
    arch_enable_interrupt();
}

void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    return ptr;
}

void *realloc(void *ptr, size_t newsize)
{
    arch_disable_interrupt();
    void *n_ptr = mpool_realloc(&pool, ptr, newsize);
    arch_enable_interrupt();
    return n_ptr;
}

void *reallocarray(void *ptr, size_t n, size_t size)
{
    return realloc(ptr, n * size);
}

void *aligned_alloc(size_t align, size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    arch_enable_interrupt();
    return ptr;
}

size_t malloc_usable_size(void *ptr)
{
    arch_disable_interrupt();
    size_t size = mpool_msize(&pool, ptr);
    arch_enable_interrupt();
    return size;
}

void *memalign(size_t align, size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    arch_enable_interrupt();
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_aligned_alloc(&pool, size, alignment);
    arch_enable_interrupt();
    if (ptr == NULL)
        return 1;
    *memptr = ptr;
    return 0;
}

void *valloc(size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    arch_enable_interrupt();
    return ptr;
}

void *pvalloc(size_t size)
{
    arch_disable_interrupt();
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    arch_enable_interrupt();
    return ptr;
}

void init_heap()
{
    map_page_range(get_current_page_dir(false), (uint64_t)KERNEL_HEAP_START, 0, KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);

    mpool_init(&pool, (void *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
}

void heap_init()
{
    init_heap();
}
