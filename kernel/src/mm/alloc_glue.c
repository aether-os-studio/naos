#include <mm/alloc_glue.h>
#include <mm/mm.h>
#include <drivers/logger.h>
#include <mod/dlinker.h>

int dlmalloc_errno;
MLOCK_T malloc_global_mutex = SPIN_INIT;

#define KERNEL_SBRK_HEAP_SIZE ((uintptr_t)(256 * 1024 * 1024))

static spinlock_t kernel_sbrk_lock = SPIN_INIT;
static bool kernel_sbrk_ready;
static uintptr_t kernel_sbrk_heap_start;
static uintptr_t kernel_sbrk_heap_end;
static uintptr_t kernel_sbrk_brk;
static uintptr_t kernel_sbrk_mapped_end;

extern char __kernel_image_end[];

static uintptr_t kernel_sbrk_choose_heap_start(void) {
    uintptr_t start = PADDING_UP((uintptr_t)&__kernel_image_end, 1UL << 30);
    uintptr_t min_start = 0xffffffffc0000000ULL;
    uintptr_t max_start = KERNEL_MODULES_SPACE_START - KERNEL_SBRK_HEAP_SIZE;

    if (start < min_start)
        start = min_start;
    if (start > max_start)
        start = max_start;

    return start;
}

static bool kernel_sbrk_init_locked(void) {
    if (kernel_sbrk_ready)
        return true;

    kernel_sbrk_heap_start = kernel_sbrk_choose_heap_start();
    kernel_sbrk_heap_end = kernel_sbrk_heap_start + KERNEL_SBRK_HEAP_SIZE;
    kernel_sbrk_brk = kernel_sbrk_heap_start;
    kernel_sbrk_mapped_end = kernel_sbrk_heap_start;
    kernel_sbrk_ready = true;
    return true;
}

static bool kernel_sbrk_map_until_locked(uintptr_t target) {
    uintptr_t map_to = PADDING_UP(target, PAGE_SIZE);

    if (map_to <= kernel_sbrk_mapped_end)
        return true;
    if (map_to > kernel_sbrk_heap_end)
        return false;

    uint64_t ret = map_page_range(get_kernel_page_dir(), kernel_sbrk_mapped_end,
                                  (uint64_t)-1, map_to - kernel_sbrk_mapped_end,
                                  PT_FLAG_R | PT_FLAG_W);
    if (ret != 0) {
        unmap_page_range(get_kernel_page_dir(), kernel_sbrk_mapped_end,
                         map_to - kernel_sbrk_mapped_end);
        dlmalloc_errno = ENOMEM;
        return false;
    }

    kernel_sbrk_mapped_end = map_to;
    return true;
}

void *sbrk(ptrdiff_t increment) {
    spin_lock(&kernel_sbrk_lock);

    if (!kernel_sbrk_init_locked()) {
        spin_unlock(&kernel_sbrk_lock);
        return (void *)-1;
    }

    uintptr_t old_brk = kernel_sbrk_brk;
    uintptr_t new_brk;

    if (increment >= 0) {
        uintptr_t grow = (uintptr_t)increment;
        if (grow > kernel_sbrk_heap_end - old_brk) {
            dlmalloc_errno = ENOMEM;
            spin_unlock(&kernel_sbrk_lock);
            return (void *)-1;
        }
        new_brk = old_brk + grow;
        if (!kernel_sbrk_map_until_locked(new_brk)) {
            spin_unlock(&kernel_sbrk_lock);
            return (void *)-1;
        }
    } else {
        uintptr_t shrink = (uintptr_t)(-(increment + 1)) + 1;
        if (shrink > old_brk - kernel_sbrk_heap_start) {
            dlmalloc_errno = ENOMEM;
            spin_unlock(&kernel_sbrk_lock);
            return (void *)-1;
        }
        new_brk = old_brk - shrink;
    }

    kernel_sbrk_brk = new_brk;
    spin_unlock(&kernel_sbrk_lock);
    return (void *)old_brk;
}

int ACQUIRE_LOCK(MLOCK_T *lock) {
    spin_lock(lock);
    return 0;
}
int RELEASE_LOCK(MLOCK_T *lock) {
    spin_unlock(lock);
    return 0;
}
int INITIAL_LOCK(MLOCK_T *lock) {
    spin_init(lock);
    return 0;
}

static void abort_print_symbol(uintptr_t addr, int level) {
    symbol_lookup_result_t symbol = {0};

    if (!dlinker_lookup_symbol_by_addr(addr, &symbol) || symbol.name == NULL) {
        printk("#%02d <unknown> address:%#018lx\n", level, addr);
        return;
    }

    if (symbol.is_module) {
        if (symbol.symbol_size != 0) {
            printk("#%02d %s+%#lx/%#lx [%s] address:%#018lx%s\n", level,
                   symbol.name, symbol.offset, symbol.symbol_size,
                   symbol.module_name ? symbol.module_name : "<module>", addr,
                   symbol.exact_match ? "" : " (nearest)");
        } else {
            printk("#%02d %s+%#lx [%s] address:%#018lx%s\n", level, symbol.name,
                   symbol.offset,
                   symbol.module_name ? symbol.module_name : "<module>", addr,
                   symbol.exact_match ? "" : " (nearest)");
        }
        return;
    }

    if (symbol.symbol_size != 0) {
        printk("#%02d %s+%#lx/%#lx [kernel] address:%#018lx%s\n", level,
               symbol.name, symbol.offset, symbol.symbol_size, addr,
               symbol.exact_match ? "" : " (nearest)");
    } else {
        printk("#%02d %s+%#lx [kernel] address:%#018lx%s\n", level, symbol.name,
               symbol.offset, addr, symbol.exact_match ? "" : " (nearest)");
    }
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif

#if defined(__loongarch64__)
#define ABORT_PRINT_RETURN_ADDRESS(level)                                      \
    do {                                                                       \
        uintptr_t addr = 0;                                                    \
        if ((level) == 0)                                                      \
            addr = (uintptr_t)__builtin_return_address(0);                     \
        if (addr == 0)                                                         \
            goto abort_trace_done;                                             \
        if (addr < get_physical_memory_offset())                               \
            goto abort_trace_done;                                             \
        abort_print_symbol(addr, level);                                       \
    } while (0)
#elif defined(__GNUC__) || defined(__clang__)
#define ABORT_PRINT_RETURN_ADDRESS(level)                                      \
    do {                                                                       \
        uintptr_t addr = (uintptr_t)__builtin_return_address(level);           \
        if (addr < get_physical_memory_offset())                               \
            goto abort_trace_done;                                             \
        abort_print_symbol(addr, level);                                       \
    } while (0)
#endif

void abort() {
    printk("======== abort traceback =======\n");

    ABORT_PRINT_RETURN_ADDRESS(0);
    ABORT_PRINT_RETURN_ADDRESS(1);
    ABORT_PRINT_RETURN_ADDRESS(2);
    ABORT_PRINT_RETURN_ADDRESS(3);
    ABORT_PRINT_RETURN_ADDRESS(4);
    ABORT_PRINT_RETURN_ADDRESS(5);
    ABORT_PRINT_RETURN_ADDRESS(6);
    ABORT_PRINT_RETURN_ADDRESS(7);
    ABORT_PRINT_RETURN_ADDRESS(8);
    ABORT_PRINT_RETURN_ADDRESS(9);
    ABORT_PRINT_RETURN_ADDRESS(10);
    ABORT_PRINT_RETURN_ADDRESS(11);
    ABORT_PRINT_RETURN_ADDRESS(12);
    ABORT_PRINT_RETURN_ADDRESS(13);
    ABORT_PRINT_RETURN_ADDRESS(14);
    ABORT_PRINT_RETURN_ADDRESS(15);
    ABORT_PRINT_RETURN_ADDRESS(16);
    ABORT_PRINT_RETURN_ADDRESS(17);
    ABORT_PRINT_RETURN_ADDRESS(18);
    ABORT_PRINT_RETURN_ADDRESS(19);
    ABORT_PRINT_RETURN_ADDRESS(20);
    ABORT_PRINT_RETURN_ADDRESS(21);
    ABORT_PRINT_RETURN_ADDRESS(22);
    ABORT_PRINT_RETURN_ADDRESS(23);
    ABORT_PRINT_RETURN_ADDRESS(24);
    ABORT_PRINT_RETURN_ADDRESS(25);
    ABORT_PRINT_RETURN_ADDRESS(26);
    ABORT_PRINT_RETURN_ADDRESS(27);
    ABORT_PRINT_RETURN_ADDRESS(28);
    ABORT_PRINT_RETURN_ADDRESS(29);
    ABORT_PRINT_RETURN_ADDRESS(30);
    ABORT_PRINT_RETURN_ADDRESS(31);

abort_trace_done:
    printk("======== abort traceback end =======\n");

    ASSERT(!"Out of memory!!!");
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
