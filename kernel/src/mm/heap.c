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

struct MemorySpan heap_oom(size_t size) {
    size_t allocate_size =
        MAX(PADDING_UP(size, DEFAULT_PAGE_SIZE), KERNEL_HEAP_SIZE);
    void *ptr = alloc_frames_bytes(allocate_size);
    return (struct MemorySpan){.ptr = ptr, .size = ptr ? allocate_size : 0};
}

void heap_init_alloc() {
    map_page_range(get_current_page_dir(false), KERNEL_HEAP_START, (uint64_t)-1,
                   KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    heap_init((uint8_t *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
    heap_onerror(heap_err);
    heap_set_oom_handler(heap_oom);
}
