#include <arch/arch.h>
#include <boot/boot.h>
#include <mm/bitmap.h>
#include <mm/buddy.h>
#include <mm/mm.h>
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
    return (void *)phys_to_virt(
        alloc_frames_early((size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
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

static void process_memory_region(uintptr_t start, uintptr_t end) {
    // 对齐
    start = (start + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);
    end = end & ~(DEFAULT_PAGE_SIZE - 1);

    if (start >= end)
        return;

    // 检查是否在 bitmap 中标记为可用
    size_t start_frame = start / DEFAULT_PAGE_SIZE;
    size_t end_frame = end / DEFAULT_PAGE_SIZE;

    uintptr_t current = start;

    while (current < end) {
        // 确定当前位置所属的 zone
        enum zone_type zone_type =
            pfn_to_zone_type(current / DEFAULT_PAGE_SIZE);

        // 找到同一 zone 的连续区域
        uintptr_t zone_end = get_zone_boundary(zone_type);
        if (zone_end > end)
            zone_end = end;

        // 检查这段区域是否在 bitmap 中可用
        uint64_t last_non_usable_addr = current;
        for (size_t frame = current / DEFAULT_PAGE_SIZE;
             frame < zone_end / DEFAULT_PAGE_SIZE; frame++) {
            if (!bitmap_get(&usable_regions, frame)) {
                last_non_usable_addr = (frame + 1) * DEFAULT_PAGE_SIZE;
            }
        }

        if (zone_end > last_non_usable_addr) {
            add_memory_region(last_non_usable_addr, zone_end, zone_type);
        }

        current = zone_end;
    }
}

void frame_init() {
    hhdm_init();

    boot_memory_map_t *memory_map = boot_get_memory_map();

    memory_size = get_memory_size();

    size_t bitmap_size = (memory_size / DEFAULT_PAGE_SIZE + 7) / 8;
    uint64_t bitmap_address = 0;

    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

        if (region->type == USABLE) {
            if (region->len >= bitmap_size) {
                bitmap_address = region->addr;
                break;
            }
        }
    }

    bitmap_init(&usable_regions, (uint8_t *)phys_to_virt(bitmap_address),
                bitmap_size);

    size_t origin_frames = 0;
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

        size_t start_frame = region->addr / DEFAULT_PAGE_SIZE;
        size_t frame_count = region->len / DEFAULT_PAGE_SIZE;

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

        if (region->type == USABLE) {
            origin_frames += frame_count;
            bitmap_set_range(&usable_regions, start_frame,
                             start_frame + frame_count, true);
        }
    }

#if defined(__x86_64__)
    size_t low_1M_frame_count = 0x100000 / DEFAULT_PAGE_SIZE;
    bitmap_set_range(&usable_regions, 0, low_1M_frame_count, false);
#endif

    size_t bitmap_frame_start = bitmap_address / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_end =
        (bitmap_address + bitmap_size + DEFAULT_PAGE_SIZE - 1) /
        DEFAULT_PAGE_SIZE;
    bitmap_set_range(&usable_regions, bitmap_frame_start, bitmap_frame_end,
                     false);

    zones_init();

    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        boot_memory_map_entry_t *region = &memory_map->entries[i];

#if defined(__x86_64__)
        if (region->addr < 0x100000)
            continue;
#endif

        if (region->type != USABLE)
            continue;

        uint64_t addr = region->addr;
        uint64_t len = region->len;

        if (addr == bitmap_address) {
            addr += (bitmap_size + DEFAULT_PAGE_SIZE - 1) &
                    ~(DEFAULT_PAGE_SIZE - 1);
            len -= (bitmap_size + DEFAULT_PAGE_SIZE - 1) &
                   ~(DEFAULT_PAGE_SIZE - 1);
        }

        process_memory_region(addr, addr + len);
    }
}

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                    uint64_t size, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == 0) {
            uint64_t phys = alloc_frames(1);
            if (phys == 0) {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags), true);
        } else {
            map_page(pml4, va, paddr + (va - vaddr),
                     get_arch_page_table_flags(flags), true);
        }
    }
}

void map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                            uint64_t size, uint64_t flags) {
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == 0) {
            uint64_t phys = alloc_frames(1);
            if (phys == 0) {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags), false);
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

static size_t next_power_of_2(size_t n) {
    if (n == 0)
        return 1;
    if ((n & (n - 1)) == 0)
        return n; // 已经是2的幂次

    size_t power = 1;
    while (power < n) {
        power <<= 1;
    }
    return power;
}

static size_t log2_floor(size_t n) {
    size_t log = 0;
    while (n > 1) {
        n >>= 1;
        log++;
    }
    return log;
}

// 分配页框
uintptr_t alloc_frames(size_t count) {
    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages);

    page_t *page = alloc_pages(GFP_KERNEL_NORMAL, order);
    if (!page) {
        page = alloc_pages(GFP_KERNEL_DMA32, order);
    }
    if (!page)
        return 0;

    uint64_t idx = page - mem_map;

    return idx * DEFAULT_PAGE_SIZE;
}

// 释放页框
void free_frames(uintptr_t addr, size_t count) {
    if (!addr)
        return;

    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages);

    uint64_t idx = addr / DEFAULT_PAGE_SIZE;
    if (bitmap_get(&usable_regions, idx) == false)
        return;

    page_t *page = &mem_map[idx];

    __free_pages(page, order);
}

uintptr_t alloc_frames_dma32(size_t count) {
    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages);

    page_t *page = alloc_pages(GFP_KERNEL_DMA32, order);
    if (!page) {
        page = alloc_pages(GFP_KERNEL_NORMAL, order);
    }
    if (!page)
        return 0;

    uint64_t idx = page - mem_map;

    uint64_t paddr = idx * DEFAULT_PAGE_SIZE;
    uint64_t vaddr = phys_to_virt(paddr);
    map_change_attribute_range(get_current_page_dir(false), vaddr,
                               count * DEFAULT_PAGE_SIZE,
                               PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);
    return paddr;
}

void free_frames_dma32(uintptr_t addr, size_t count) {
    uint64_t vaddr = phys_to_virt(addr);
    map_change_attribute_range(get_current_page_dir(false), vaddr,
                               count * DEFAULT_PAGE_SIZE,
                               PT_FLAG_R | PT_FLAG_W);
    return free_frames(addr, count);
}
