#include "heap.h"
#include "mm/mm.h"
#include "mm/hhdm.h"

static struct mpool pool;

spinlock_t heap_op_lock = {0};

uint64_t get_all_memusage()
{
    return KERNEL_HEAP_SIZE;
}

void *calloc(size_t n, size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    if (__builtin_mul_overflow(n, size, &size))
    {
        spin_unlock_irqrestore(&heap_op_lock);
        return NULL;
    }
    spin_unlock(&heap_op_lock);
    void *ptr = malloc(size);
    spin_lock(&heap_op_lock);
    if (ptr == NULL)
    {
        return NULL;

        spin_unlock_irqrestore(&heap_op_lock);
    }
    memset(ptr, 0, size);
    spin_unlock_irqrestore(&heap_op_lock);

    return ptr;
}

void *malloc(size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_alloc(&pool, size);
    spin_unlock_irqrestore(&heap_op_lock);
    return ptr;
}

void free(void *ptr)
{
    spin_lock_irqsave(&heap_op_lock);
    mpool_free(&pool, ptr);
    spin_unlock_irqrestore(&heap_op_lock);
}

void *xmalloc(size_t size)
{
    spin_unlock(&heap_op_lock);
    void *ptr = malloc(size);
    spin_lock(&heap_op_lock);
    return ptr;
}

void *realloc(void *ptr, size_t newsize)
{
    spin_lock_irqsave(&heap_op_lock);
    void *n_ptr = mpool_realloc(&pool, ptr, newsize);
    spin_unlock_irqrestore(&heap_op_lock);
    return n_ptr;
}

void *reallocarray(void *ptr, size_t n, size_t size)
{
    return realloc(ptr, n * size);
}

void *aligned_alloc(size_t align, size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    spin_unlock_irqrestore(&heap_op_lock);
    return ptr;
}

size_t malloc_usable_size(void *ptr)
{
    spin_lock_irqsave(&heap_op_lock);
    size_t size = mpool_msize(&pool, ptr);
    spin_unlock_irqrestore(&heap_op_lock);
    return size;
}

void *memalign(size_t align, size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_aligned_alloc(&pool, size, align);
    spin_unlock_irqrestore(&heap_op_lock);
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_aligned_alloc(&pool, size, alignment);
    if (ptr == NULL)
    {
        spin_unlock_irqrestore(&heap_op_lock);
        return 1;
    }
    *memptr = ptr;
    spin_unlock_irqrestore(&heap_op_lock);
    return 0;
}

void *valloc(size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    spin_unlock_irqrestore(&heap_op_lock);
    return ptr;
}

void *pvalloc(size_t size)
{
    spin_lock_irqsave(&heap_op_lock);
    void *ptr = mpool_aligned_alloc(&pool, size, PAGE_SIZE);
    spin_unlock_irqrestore(&heap_op_lock);
    return ptr;
}

void init_heap()
{
    map_page_range(get_current_page_dir(false), (uint64_t)KERNEL_HEAP_START, 0, KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    memset((void *)KERNEL_HEAP_START, 0, KERNEL_HEAP_SIZE);
    mpool_init(&pool, (void *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
}

void heap_init()
{
    init_heap();
}
