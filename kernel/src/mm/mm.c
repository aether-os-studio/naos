#include <arch/arch.h>
#include <boot/boot.h>
#include <mm/bitmap.h>
#include <mm/buddy.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <drivers/kernel_logger.h>

spinlock_t frame_op_lock = SPIN_INIT;

Bitmap usable_regions;
uint64_t memory_size = 0;

static size_t early_last_alloc_pos = 0;

uint64_t alloc_frames_early(size_t count) {
    spin_lock(&frame_op_lock);
    Bitmap *bitmap = &usable_regions;
    size_t frame_index =
        bitmap_find_range_from(bitmap, count, true, early_last_alloc_pos);
    bitmap_set_range(bitmap, frame_index, frame_index + count, false);
    early_last_alloc_pos = frame_index + count - 1;
    spin_unlock(&frame_op_lock);
    return frame_index * DEFAULT_PAGE_SIZE;
}

void *early_alloc(size_t size) {
    void *ptr = (void *)phys_to_virt(
        alloc_frames_early((size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
    memset(ptr, 0, (size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1));
    return ptr;
}

uint64_t get_memory_size() {
    uint64_t all_memory_size = 0;
    boot_memory_map_t *memory_map = boot_get_memory_map();

    for (uint64_t i = memory_map->entry_count - 1; i > 0; i--) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];
        if (region->type == USABLE) {
            all_memory_size = region->addr + region->len;
            break;
        }
    }

    return all_memory_size;
}

static uintptr_t get_zone_boundary(enum zone_type type) {
    switch (type) {
#if defined(__x86_64__)
    case ZONE_DMA:
        return ZONE_DMA_END;
#endif
    case ZONE_DMA32:
        return ZONE_DMA32_END;
    case ZONE_NORMAL:
        return UINTPTR_MAX;
    default:
        return 0;
    }
}

// 处理单个内存区域，正确处理不连续的可用帧
static void process_memory_region(uintptr_t start, uintptr_t end) {
    // 页对齐
    start = PADDING_UP(start, DEFAULT_PAGE_SIZE);
    end = PADDING_DOWN(end, DEFAULT_PAGE_SIZE);

    if (start >= end)
        return;

    uintptr_t current = start;

    while (current < end) {
        // 确定当前位置所属的 zone
        enum zone_type type = phys_to_zone_type(current);

        // 找到同一 zone 的边界
        uintptr_t zone_boundary = get_zone_boundary(type);
        uintptr_t zone_end = MIN(zone_boundary, end);

        // 在当前 zone 内查找连续的可用区域
        uintptr_t region_current = current;

        while (region_current < zone_end) {
            size_t frame = region_current / DEFAULT_PAGE_SIZE;

            // 跳过不可用的帧
            while (region_current < zone_end &&
                   !bitmap_get(&usable_regions,
                               region_current / DEFAULT_PAGE_SIZE)) {
                region_current += DEFAULT_PAGE_SIZE;
            }

            if (region_current >= zone_end)
                break;

            // 找到连续可用区域的起始
            uintptr_t usable_start = region_current;

            // 找到连续可用区域的结束
            while (region_current < zone_end &&
                   bitmap_get(&usable_regions,
                              region_current / DEFAULT_PAGE_SIZE)) {
                region_current += DEFAULT_PAGE_SIZE;
            }

            uintptr_t usable_end = region_current;

            // 添加这段连续可用的区域到 buddy 分配器
            if (usable_end > usable_start) {
                add_memory_region(usable_start, usable_end, type);
            }
        }

        current = zone_end;
    }
}

void frame_init(void) {
    hhdm_init();

    boot_memory_map_t *memory_map = boot_get_memory_map();
    memory_size = get_memory_size();

    // 计算 bitmap 大小
    size_t total_frames = memory_size / DEFAULT_PAGE_SIZE;
    size_t bitmap_size = (total_frames + 7) / 8;
    size_t bitmap_size_aligned = PADDING_UP(bitmap_size, DEFAULT_PAGE_SIZE);

    uint64_t bitmap_address = 0;

    // 查找存放 bitmap 的位置
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

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

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

        if (region->type == USABLE) {
            size_t start_frame = region->addr / DEFAULT_PAGE_SIZE;
            size_t end_frame = (region->addr + region->len) / DEFAULT_PAGE_SIZE;

            if (end_frame > start_frame) {
                bitmap_set_range(&usable_regions, start_frame, end_frame, true);
            }
        }
    }

#if defined(__x86_64__)
    // 保留低 1MB
    size_t low_1M_frames = 0x100000 / DEFAULT_PAGE_SIZE;
    bitmap_set_range(&usable_regions, 0, low_1M_frames, false);
#endif

    // 标记 bitmap 自身占用的区域为不可用
    size_t bitmap_frame_start = bitmap_address / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_end =
        PADDING_UP(bitmap_address + bitmap_size, DEFAULT_PAGE_SIZE) /
        DEFAULT_PAGE_SIZE;
    bitmap_set_range(&usable_regions, bitmap_frame_start, bitmap_frame_end,
                     false);

    page_init();

    // 初始化 buddy 分配器
    buddy_init();

    // 将可用内存添加到 buddy 分配器
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

        if (region->type != USABLE)
            continue;

        uintptr_t addr = region->addr;
        uintptr_t region_end = region->addr + region->len;

        // 跳过 bitmap 占用的部分
        if (addr <= bitmap_address && bitmap_address < region_end) {
            // bitmap 在这个区域内
            uintptr_t bitmap_end =
                PADDING_UP(bitmap_address + bitmap_size, DEFAULT_PAGE_SIZE);

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

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                    uint64_t size, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == (uint64_t)-1) {
            map_page(pml4, va, (uint64_t)-1, get_arch_page_table_flags(flags),
                     true);
        } else {
            map_page(pml4, va, paddr + (va - vaddr),
                     get_arch_page_table_flags(flags), true);
        }
    }
}

void map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                            uint64_t size, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == (uint64_t)-1) {
            map_page(pml4, va, (uint64_t)-1, get_arch_page_table_flags(flags),
                     false);
        } else {
            map_page(pml4, va, paddr + (va - vaddr),
                     get_arch_page_table_flags(flags), false);
        }
    }
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size) {
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        unmap_page(pml4, va);
    }
}

uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + len; va += DEFAULT_PAGE_SIZE) {
        map_change_attribute(pgdir, va, get_arch_page_table_flags(flags));
    }

    return 0;
}
