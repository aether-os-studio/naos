#include <mm/heap.h>
#include <libs/klibc.h>

spinlock_t heap_lock = SPIN_INIT;

void *malloc(size_t size) {
    spin_lock(&heap_lock);
    void *ptr = liballoc_malloc(size);
    spin_unlock(&heap_lock);
    return ptr;
}

void *calloc(size_t nmemb, size_t size) {
    spin_lock(&heap_lock);
    void *ptr = liballoc_calloc(nmemb, size);
    spin_unlock(&heap_lock);
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    spin_lock(&heap_lock);
    void *nptr = liballoc_realloc(ptr, size);
    spin_unlock(&heap_lock);
    return nptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
    spin_lock(&heap_lock);
    size = PADDING_UP(size, alignment);
    void *ptr = liballoc_aligned_alloc(alignment, size);
    spin_unlock(&heap_lock);
    return ptr;
}

void free(void *ptr) {
    spin_lock(&heap_lock);
    liballoc_free(ptr);
    spin_unlock(&heap_lock);
}
