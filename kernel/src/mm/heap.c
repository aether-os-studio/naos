#include <mm/heap.h>
#include <mm/mm.h>

void heap_err(enum HeapError error, void *ptr) {
    switch (error) {
    case InvalidFree:
        printk("Heap Error: Invalid Free at %p\n", ptr);
        break;
    case LayoutError:
        printk("Heap Error: Layout Error at %p\n", ptr);
        break;
    default:
        printk("Heap Error: Unknown Error at %p\n", ptr);
        break;
    }
}

void heap_init_alloc() {
    map_page_range(get_current_page_dir(false), KERNEL_HEAP_START, 0,
                   KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    memset((void *)KERNEL_HEAP_START, 0, KERNEL_HEAP_SIZE);
    heap_init((uint8_t *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
    heap_onerror(heap_err);
}
