#include <mm/heap.h>
#include <mm/mm.h>

void heap_init_alloc() {
    map_page_range(get_current_page_dir(false), KERNEL_HEAP_START, 0,
                   KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    memset((void *)KERNEL_HEAP_START, 0, KERNEL_HEAP_SIZE);
    heap_init((uint8_t *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
}

void *calloc(size_t num, size_t size) {
    void *ptr = malloc(num * size);
    if (ptr)
        memset(ptr, 0, num * size);
    return ptr;
}
