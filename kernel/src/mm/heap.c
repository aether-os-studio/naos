#include <mm/heap.h>
#include <mm/mm.h>

uint64_t heap_ptr = KERNEL_HEAP_START;

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

struct MemorySpan heap_oom(size_t size) {
    size_t allocate_size =
        MAX(PADDING_UP(size, DEFAULT_PAGE_SIZE), KERNEL_HEAP_SIZE);
    uint64_t ptr = heap_ptr;
    heap_ptr += allocate_size;
    map_page_range(get_current_page_dir(false), ptr, (uint64_t)-1,
                   allocate_size, PT_FLAG_R | PT_FLAG_W);
    return (struct MemorySpan){.ptr = (uint8_t *)ptr, .size = allocate_size};
}

void heap_init_alloc() {
    map_page_range(get_current_page_dir(false), heap_ptr, (uint64_t)-1,
                   KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    heap_init((void *)heap_ptr, KERNEL_HEAP_SIZE);
    heap_ptr += KERNEL_HEAP_SIZE;
    heap_onerror(heap_err);
    heap_set_oom_handler(heap_oom);
}
