#include <arch/arch.h>
#include <boot/boot.h>
#include <mm/bitmap.h>
#include <mm/buddy.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <task/task.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <drivers/logger.h>

spinlock_t frame_op_lock = SPIN_INIT;

Bitmap usable_regions;
uint64_t memory_size = 0;

static size_t early_last_alloc_pos = 0;

#define USER_LAYOUT_ASLR_BITS 18

static uint64_t mmap_aslr_state;

uint64_t arch_user_va_limit(void) __attribute__((weak));

uint64_t arch_user_va_limit(void) { return 0; }

uint64_t user_va_limit(void) {
    uint64_t limit = arch_user_va_limit();
    if (limit == 0) {
        limit = get_physical_memory_offset();
        if (limit == 0)
            return UINT64_MAX;
        limit--;
    }
    return limit;
}

uint64_t mm_default_mmap_top(void) {
    uint64_t va_limit = user_va_limit();
    uint64_t limit = va_limit == UINT64_MAX
                         ? PADDING_DOWN(UINT64_MAX, PAGE_SIZE)
                         : PADDING_DOWN(va_limit + 1, PAGE_SIZE);
    if (limit <= USER_STACK_END - USER_MMAP_BASE_END)
        return USER_MMAP_START;
    limit =
        PADDING_DOWN(limit - (USER_STACK_END - USER_MMAP_BASE_END), PAGE_SIZE);
    if (limit <= USER_MMAP_START)
        return USER_MMAP_START;
    return limit;
}

static uint64_t mmap_aslr_next(void) {
    uint64_t seed = mmap_aslr_state;
    if (seed == 0) {
        seed = nano_time() ^ (boot_get_boottime() << 32) ^
               (uint64_t)(uintptr_t)&seed ^
               (uint64_t)(uintptr_t)get_kernel_page_dir();
    }

    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    if (seed == 0)
        seed = 0x9e3779b97f4a7c15ULL;
    mmap_aslr_state = seed;
    return seed;
}

void task_mm_init_aslr(task_mm_info_t *mm) {
    if (!mm)
        return;

    uint64_t default_layout_top =
        task_mm_mmap_top(NULL) + (USER_STACK_END - USER_MMAP_BASE_END);
    uint64_t layout_top = default_layout_top;
    uint64_t template_top = USER_STACK_END;
    uint64_t slide = 0;

    if (layout_top > template_top) {
        uint64_t max_slide = layout_top - template_top;
        uint64_t window = (1ULL << USER_LAYOUT_ASLR_BITS) * PAGE_SIZE;
        uint64_t min_layout_top =
            max_slide > window ? layout_top - window : template_top;
        uint64_t span_pages = (layout_top - min_layout_top) / PAGE_SIZE;

        if (span_pages)
            layout_top -= (mmap_aslr_next() % (span_pages + 1)) * PAGE_SIZE;

        slide = layout_top - template_top;
    }

    mm->mmap_top = USER_MMAP_BASE_END + slide;
    mm->signal_trampoline_start = USER_SIGNAL_TRAMPOLINE_START + slide;
    mm->pie_base = PIE_BASE_ADDR + slide;
    mm->interpreter_base = INTERPRETER_BASE_ADDR + slide;
    mm->brk_start = USER_BRK_START + slide;
    mm->brk_current = mm->brk_start;
    mm->brk_end = USER_BRK_END + slide;
    mm->stack_start = USER_STACK_START + slide;
    mm->stack_end = USER_STACK_END + slide;
}

uint64_t task_mm_mmap_top(task_mm_info_t *mm) {
    if (!mm)
        return mm_default_mmap_top();
    if (mm->mmap_top < USER_MMAP_START)
        task_mm_init_aslr(mm);
    return mm->mmap_top;
}

uint64_t task_mm_signal_trampoline_start(task_mm_info_t *mm) {
    if (!mm)
        return USER_SIGNAL_TRAMPOLINE_START;
    if (!mm->signal_trampoline_start)
        task_mm_init_aslr(mm);
    return mm->signal_trampoline_start;
}

uint64_t task_mm_signal_trampoline_end(task_mm_info_t *mm) {
    return task_mm_signal_trampoline_start(mm) + PAGE_SIZE;
}

uint64_t task_mm_pie_base(task_mm_info_t *mm) {
    if (!mm)
        return PIE_BASE_ADDR;
    if (!mm->pie_base)
        task_mm_init_aslr(mm);
    return mm->pie_base;
}

uint64_t task_mm_interpreter_base(task_mm_info_t *mm) {
    if (!mm)
        return INTERPRETER_BASE_ADDR;
    if (!mm->interpreter_base)
        task_mm_init_aslr(mm);
    return mm->interpreter_base;
}

uint64_t task_mm_stack_start(task_mm_info_t *mm) {
    if (!mm)
        return USER_STACK_START;
    if (!mm->stack_start)
        task_mm_init_aslr(mm);
    return mm->stack_start;
}

uint64_t task_mm_stack_end(task_mm_info_t *mm) {
    if (!mm)
        return USER_STACK_END;
    if (!mm->stack_end)
        task_mm_init_aslr(mm);
    return mm->stack_end;
}

bool task_mm_flush_tlb_page(task_mm_info_t *mm, uint64_t vaddr)
    __attribute__((weak));

bool task_mm_flush_tlb_page(task_mm_info_t *mm, uint64_t vaddr) {
    (void)mm;
    arch_flush_tlb(vaddr);
    return true;
}

bool task_mm_flush_tlb_all(task_mm_info_t *mm) __attribute__((weak));

bool task_mm_flush_tlb_all(task_mm_info_t *mm) {
    (void)mm;
    arch_flush_tlb_all();
    return true;
}

uint64_t alloc_frames_early(size_t count) {
    if (count == 0)
        return UINT64_MAX;

    spin_lock(&frame_op_lock);
    Bitmap *bitmap = &usable_regions;
    size_t frame_index =
        bitmap_find_range_from(bitmap, count, true, early_last_alloc_pos);
    if (frame_index == (size_t)-1 || frame_index + count > bitmap->length) {
        spin_unlock(&frame_op_lock);
        return UINT64_MAX;
    }
    bitmap_set_range(bitmap, frame_index, frame_index + count, false);
    early_last_alloc_pos = frame_index + count;
    spin_unlock(&frame_op_lock);
    return frame_index * PAGE_SIZE;
}

void *early_alloc(size_t size) {
    if (size == 0)
        return NULL;

    size_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t phys = alloc_frames_early(aligned_size / PAGE_SIZE);
    if (phys == UINT64_MAX)
        return NULL;

    void *ptr = (void *)phys_to_virt(phys);
    memset(ptr, 0, aligned_size);
    return ptr;
}

void *alloc_frames_bytes(uint64_t bytes) {
    uint64_t paddr = alloc_frames(PADDING_UP(bytes, PAGE_SIZE) / PAGE_SIZE);
    return (void *)phys_to_virt(paddr);
}

void free_frames_bytes(void *ptr, uint64_t bytes) {
    uint64_t paddr = virt_to_phys(ptr);
    free_frames(paddr, PADDING_UP(bytes, PAGE_SIZE) / PAGE_SIZE);
}

uint64_t get_memory_size() {
    uint64_t all_memory_size = 0;
    boot_memory_map_t *memory_map = boot_get_memory_map();

    if (!memory_map || memory_map->entry_count == 0)
        return 0;

    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];
        if (region->type == USABLE &&
            region->addr + region->len > all_memory_size) {
            all_memory_size = region->addr + region->len;
        }
    }

    return all_memory_size;
}

// 处理单个内存区域，正确处理不连续的可用帧
static void process_memory_region(uintptr_t start, uintptr_t end) {
    // 页对齐
    start = PADDING_UP(start, PAGE_SIZE);
    end = PADDING_DOWN(end, PAGE_SIZE);

    if (start >= end)
        return;

    uintptr_t current = start;

    while (current < end) {
        uintptr_t region_current = current;

        while (region_current < end &&
               !bitmap_get(&usable_regions, region_current / PAGE_SIZE)) {
            region_current += PAGE_SIZE;
        }

        if (region_current >= end)
            break;

        uintptr_t usable_start = region_current;

        while (region_current < end &&
               bitmap_get(&usable_regions, region_current / PAGE_SIZE)) {
            region_current += PAGE_SIZE;
        }

        uintptr_t usable_end = region_current;

        if (usable_end > usable_start) {
            add_memory_region(usable_start, usable_end, ZONE_NORMAL);
        }

        current = region_current;
    }
}

void frame_init(void) {
    hhdm_init();

    boot_memory_map_t *memory_map = boot_get_memory_map();
    memory_size = get_memory_size();

    // 计算 bitmap 大小
    size_t total_frames = memory_size / PAGE_SIZE;
    size_t bitmap_size = (total_frames + 7) / 8;
    size_t bitmap_size_aligned = PADDING_UP(bitmap_size, PAGE_SIZE);

    uint64_t bitmap_address = 0;

    // 查找存放 bitmap 的位置
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

        if (!arch_memory_region_usable(region->addr, region->len))
            continue;

        if (region->type == USABLE && region->len >= bitmap_size_aligned) {
            bitmap_address = region->addr;
            break;
        }
    }

    if (bitmap_address == 0) {
        // 无法找到足够大的区域存放 bitmap
        ASSERT(!"Cannot find memory for frame bitmap");
    }

    // 初始化 bitmap（所有位初始为 0 = 不可用）
    bitmap_init(&usable_regions, (uint8_t *)phys_to_virt(bitmap_address),
                bitmap_size);

    // 标记可用区域
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

        if (!arch_memory_region_usable(region->addr, region->len))
            continue;

        if (region->type == USABLE) {
            size_t start_frame = region->addr / PAGE_SIZE;
            size_t end_frame = (region->addr + region->len) / PAGE_SIZE;

            if (end_frame > start_frame) {
                bitmap_set_range(&usable_regions, start_frame, end_frame, true);
            }
        }
    }

    // 标记 bitmap 自身占用的区域为不可用
    size_t bitmap_frame_start = bitmap_address / PAGE_SIZE;
    size_t bitmap_frame_end =
        PADDING_UP(bitmap_address + bitmap_size, PAGE_SIZE) / PAGE_SIZE;
    bitmap_set_range(&usable_regions, bitmap_frame_start, bitmap_frame_end,
                     false);

    page_init();

    // 初始化 buddy 分配器
    buddy_init();

    // 将可用内存添加到 buddy 分配器
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

        if (!arch_memory_region_usable(region->addr, region->len))
            continue;

        if (region->type != USABLE)
            continue;

        uintptr_t addr = region->addr;
        uintptr_t region_end = region->addr + region->len;

        // 跳过 bitmap 占用的部分
        if (addr <= bitmap_address && bitmap_address < region_end) {
            // bitmap 在这个区域内
            uintptr_t bitmap_end =
                PADDING_UP(bitmap_address + bitmap_size, PAGE_SIZE);

            // 处理 bitmap 之前的部分
            if (addr < bitmap_address) {
                process_memory_region(addr, bitmap_address);
            }

            // 处理 bitmap 之后的部分
            if (bitmap_end < region_end) {
                process_memory_region(bitmap_end, region_end);
            }
        } else {
            process_memory_region(addr, region_end);
        }
    }
}

uint64_t map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                        uint64_t size, uint64_t flags) {
    ASSERT((vaddr & 0xfff) == 0);
    ASSERT(paddr == (uint64_t)-1 || (paddr & 0xfff) == 0);

    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        uint64_t ret;
        if (paddr == (uint64_t)-1) {
            ret = map_page(pml4, va, (uint64_t)-1,
                           get_arch_page_table_flags(flags), true);
        } else {
            ret = map_page(pml4, va, paddr + (va - vaddr),
                           get_arch_page_table_flags(flags), true);
        }

        if (ret != 0)
            return ret;
    }

    return 0;
}

uint64_t map_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t paddr,
                           uint64_t size, uint64_t flags) {
    uint64_t *pgdir = task_mm_pgdir(mm);
    uint64_t mapped = 0;

    if (!mm || !pgdir)
        return (uint64_t)-1;

    ASSERT((vaddr & 0xfff) == 0);
    ASSERT(paddr == (uint64_t)-1 || (paddr & 0xfff) == 0);

    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        bool had_mapping = translate_address(pgdir, va) != 0;
        uint64_t ret;

        if (paddr == (uint64_t)-1) {
            ret = map_page(pgdir, va, (uint64_t)-1,
                           get_arch_page_table_flags(flags), true);
        } else {
            ret = map_page(pgdir, va, paddr + (va - vaddr),
                           get_arch_page_table_flags(flags), true);
        }

        if (ret != 0) {
            if (mapped)
                __atomic_add_fetch(&mm->resident_pages, mapped,
                                   __ATOMIC_RELAXED);
            return ret;
        }
        if (!had_mapping && translate_address(pgdir, va)) {
            mapped++;
        }
    }

    if (mapped)
        __atomic_add_fetch(&mm->resident_pages, mapped, __ATOMIC_RELAXED);
    return 0;
}

uint64_t map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                                uint64_t size, uint64_t flags) {
    ASSERT((vaddr & 0xfff) == 0);
    ASSERT(paddr == (uint64_t)-1 || (paddr & 0xfff) == 0);

    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        uint64_t ret;
        if (paddr == (uint64_t)-1) {
            ret = map_page(pml4, va, (uint64_t)-1,
                           get_arch_page_table_flags(flags), false);
        } else {
            ret = map_page(pml4, va, paddr + (va - vaddr),
                           get_arch_page_table_flags(flags), false);
        }

        if (ret != 0)
            return ret;
    }

    return 0;
}

uint64_t map_page_range_unforce_mm(task_mm_info_t *mm, uint64_t vaddr,
                                   uint64_t paddr, uint64_t size,
                                   uint64_t flags) {
    uint64_t *pgdir = task_mm_pgdir(mm);
    uint64_t mapped = 0;

    if (!mm || !pgdir)
        return (uint64_t)-1;

    ASSERT((vaddr & 0xfff) == 0);
    ASSERT(paddr == (uint64_t)-1 || (paddr & 0xfff) == 0);

    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        bool had_mapping = translate_address(pgdir, va) != 0;
        uint64_t ret;

        if (paddr == (uint64_t)-1) {
            ret = map_page(pgdir, va, (uint64_t)-1,
                           get_arch_page_table_flags(flags), false);
        } else {
            ret = map_page(pgdir, va, paddr + (va - vaddr),
                           get_arch_page_table_flags(flags), false);
        }

        if (ret != 0) {
            if (mapped)
                __atomic_add_fetch(&mm->resident_pages, mapped,
                                   __ATOMIC_RELAXED);
            return ret;
        }
        if (!had_mapping && translate_address(pgdir, va)) {
            mapped++;
        }
    }

    if (mapped)
        __atomic_add_fetch(&mm->resident_pages, mapped, __ATOMIC_RELAXED);
    return 0;
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size) {
    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        unmap_page(pml4, va);
    }
}

void unmap_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t size) {
    if (!mm)
        return;

    uint64_t unmapped = 0;
    unmap_release_batch_t batch = {
        .mm = mm,
        .flush_start = vaddr,
        .flush_end = vaddr + size,
    };

    for (uint64_t va = vaddr; va < vaddr + size; va += PAGE_SIZE) {
        if (batch.page_count == UNMAP_RELEASE_BATCH_MAX) {
            unmap_release_batch_commit(&batch);
            batch.mm = mm;
            batch.flush_start = vaddr;
            batch.flush_end = vaddr + size;
        }

        if (unmap_page_defer_release(task_mm_pgdir(mm), va, &batch))
            unmapped++;
    }

    unmap_release_batch_commit(&batch);
    if (unmapped) {
        uint64_t old = __atomic_load_n(&mm->resident_pages, __ATOMIC_RELAXED);
        uint64_t new_value = old > unmapped ? old - unmapped : 0;
        __atomic_store_n(&mm->resident_pages, new_value, __ATOMIC_RELAXED);
    }
}

uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + len; va += PAGE_SIZE) {
        map_change_attribute(pgdir, va, get_arch_page_table_flags(flags));
    }

    return 0;
}

uint64_t map_change_attribute_range_mm(task_mm_info_t *mm, uint64_t vaddr,
                                       uint64_t len, uint64_t flags) {
    uint64_t ret =
        map_change_attribute_range(task_mm_pgdir(mm), vaddr, len, flags);

    return ret;
}
