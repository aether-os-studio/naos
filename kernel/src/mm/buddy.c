#include <mm/buddy.h>
#include <mm/bitmap.h>
#include <mm/page.h>
#include <drivers/kernel_logger.h>

extern Bitmap usable_regions;

Bitmap using_regions;

const char *zone_names[__MAX_NR_ZONES] = {
#if defined(__x86_64__)
    "DMA",
#endif
    "DMA32", "Normal"};

zone_t *zones[__MAX_NR_ZONES] = {NULL};
int nr_zones = 0;

extern uint64_t memory_size;
extern void *early_alloc(size_t size);

static inline size_t log2_floor(size_t x) {
    if (x == 0)
        return 0;
    size_t leading_zeros = __builtin_clzl(x);
    return 63 - leading_zeros;
}

static inline size_t next_power_of_2(size_t x) {
    if (x == 0)
        return 1;
    if ((x & (x - 1)) == 0)
        return x;
    return 1UL << (log2_floor(x) + 1);
}

static inline size_t order_to_index(size_t order) { return order - MIN_ORDER; }

static inline size_t index_to_order(size_t index) { return index + MIN_ORDER; }

// 获取页面列表中第 j 个条目的物理地址
static inline uintptr_t entry_phys_addr(uintptr_t page_list_paddr, size_t j) {
    return page_list_paddr + sizeof(page_list_t) + j * sizeof(uintptr_t);
}

// 获取页面列表中第 j 个条目的虚拟地址
static inline void *entry_virt_addr(uintptr_t page_list_paddr, size_t j) {
    return (void *)phys_to_virt(entry_phys_addr(page_list_paddr, j));
}

// 读取物理地址处的数据
static inline page_list_t read_page_list(uintptr_t paddr) {
    page_list_t *ptr = (page_list_t *)phys_to_virt(paddr);
    return *ptr;
}

// 写入 page_list 到物理地址
static inline void write_page_list(uintptr_t paddr, page_list_t list) {
    page_list_t *ptr = (page_list_t *)phys_to_virt(paddr);
    *ptr = list;
}

// 读取条目
static inline uintptr_t read_entry(uintptr_t page_list_paddr, size_t j) {
    uintptr_t *ptr = (uintptr_t *)entry_virt_addr(page_list_paddr, j);
    return *ptr;
}

// 写入条目
static inline void write_entry(uintptr_t page_list_paddr, size_t j,
                               uintptr_t value) {
    uintptr_t *ptr = (uintptr_t *)entry_virt_addr(page_list_paddr, j);
    *ptr = value;
}

enum zone_type phys_to_zone_type(uintptr_t phys) {
#if defined(__x86_64__)
    if (phys < ZONE_DMA_END)
        return ZONE_DMA;
#endif
    if (phys < ZONE_DMA32_END)
        return ZONE_DMA32;
    return ZONE_NORMAL;
}

zone_t *get_zone(enum zone_type type) {
    if (type >= __MAX_NR_ZONES)
        return NULL;
    return zones[type];
}

bool zone_has_memory(zone_t *zone) { return zone && zone->managed_pages > 0; }

static enum zone_type gfp_to_zone(uint32_t gfp_flags) {
#if defined(__x86_64__)
    if (gfp_flags & GFP_DMA)
        return ZONE_DMA;
#endif
    if (gfp_flags & GFP_DMA32)
        return ZONE_DMA32;
    return ZONE_NORMAL;
}

// 从指定 order 的空闲列表中弹出一个块
static uintptr_t pop_front(buddy_allocator_t *alloc, size_t order) {
    if (order < MIN_ORDER || order >= MAX_ORDER)
        return 0;

    // 尝试从指定 order 分配
    size_t index = order_to_index(order);
    uintptr_t page_list_paddr = alloc->free_area[index];

    if (page_list_paddr == 0)
        goto try_split;

    page_list_t page_list = read_page_list(page_list_paddr);

    // 跳过空的页面列表
    while (page_list.entry_num == 0) {
        uintptr_t next = page_list.next_page;
        if (next == 0)
            goto try_split;

        page_list_paddr = next;
        page_list = read_page_list(page_list_paddr);
    }

    // 从列表中取出一个条目
    if (page_list.entry_num > 0) {
        uintptr_t entry = read_entry(page_list_paddr, page_list.entry_num - 1);
        write_entry(page_list_paddr, page_list.entry_num - 1, 0);

        if (entry == 0) {
            // 不应该发生
            goto try_split;
        }

        page_list.entry_num--;
        write_page_list(page_list_paddr, page_list);

        return entry;
    }

try_split:
    // 尝试从更高 order 分裂
    for (size_t current_order = order + 1; current_order < MAX_ORDER;
         current_order++) {
        index = order_to_index(current_order);
        page_list_paddr = alloc->free_area[index];

        if (page_list_paddr == 0)
            continue;

        page_list = read_page_list(page_list_paddr);

        // 跳过空的页面列表
        while (page_list.entry_num == 0 && page_list.next_page != 0) {
            page_list_paddr = page_list.next_page;
            page_list = read_page_list(page_list_paddr);
        }

        if (page_list.entry_num == 0)
            continue;

        // 取出一个大块
        uintptr_t block = read_entry(page_list_paddr, page_list.entry_num - 1);
        write_entry(page_list_paddr, page_list.entry_num - 1, 0);
        page_list.entry_num--;
        write_page_list(page_list_paddr, page_list);

        if (block == 0)
            continue;

        // 分裂大块，将 buddy 放回较小的 order
        while (current_order > order) {
            current_order--;
            uintptr_t buddy = block + (1UL << current_order);

            // 将 buddy 放入对应 order 的空闲列表
            buddy_free_zone(container_of(alloc, zone_t, allocator), buddy,
                            current_order);
        }

        return block;
    }

    return 0; // 分配失败
}

// 释放一个块（带合并）
void buddy_free_zone(zone_t *zone, uintptr_t base, size_t order) {
    if (base == 0 || order < MIN_ORDER || order >= MAX_ORDER)
        return;

    buddy_allocator_t *alloc = &zone->allocator;

    while (order < MAX_ORDER) {
        // 检查对齐
        if ((base & ((1UL << order) - 1)) != 0) {
            // 对齐错误，直接插入不合并
            break;
        }

        // 计算 buddy 地址
        uintptr_t buddy_addr = base ^ (1UL << order);

        // 检查 buddy 是否在 zone 范围内
        if (buddy_addr < zone->zone_start_pfn * DEFAULT_PAGE_SIZE ||
            buddy_addr >= zone->zone_end_pfn * DEFAULT_PAGE_SIZE) {
            break; // buddy 不在范围内，停止合并
        }

        size_t index = order_to_index(order);
        uintptr_t first_page_list_paddr = alloc->free_area[index];

        if (first_page_list_paddr == 0)
            break; // 该 order 没有空闲列表，无法查找 buddy

        // 在空闲列表中查找 buddy
        uintptr_t page_list_paddr = first_page_list_paddr;
        page_list_t page_list = read_page_list(page_list_paddr);
        page_list_t first_page_list = page_list;

        uintptr_t buddy_entry_page_paddr = 0;
        size_t buddy_entry_index = 0;
        bool buddy_found = false;

        // 不在最高 order 时才查找 buddy
        if (order != MAX_ORDER - 1) {
            while (true) {
                for (size_t i = 0; i < page_list.entry_num; i++) {
                    uintptr_t entry = read_entry(page_list_paddr, i);
                    if (entry == buddy_addr) {
                        buddy_entry_page_paddr = page_list_paddr;
                        buddy_entry_index = i;
                        buddy_found = true;
                        break;
                    }
                }

                if (buddy_found)
                    break;

                if (page_list.next_page == 0)
                    break;

                page_list_paddr = page_list.next_page;
                page_list = read_page_list(page_list_paddr);
            }
        }

        if (buddy_found) {
            // 从空闲列表中移除 buddy
            // 找到第一个非空的页面列表
            page_list_paddr = alloc->free_area[index];
            page_list = read_page_list(page_list_paddr);

            while (page_list.entry_num == 0 && page_list.next_page != 0) {
                page_list_paddr = page_list.next_page;
                page_list = read_page_list(page_list_paddr);
            }

            if (page_list.entry_num == 0) {
                // 不应该发生
                break;
            }

            // 用最后一个条目替换 buddy 的位置
            if (page_list_paddr != buddy_entry_page_paddr) {
                // buddy 在另一个页面列表中
                uintptr_t last_entry =
                    read_entry(page_list_paddr, page_list.entry_num - 1);
                write_entry(buddy_entry_page_paddr, buddy_entry_index,
                            last_entry);
                write_entry(page_list_paddr, page_list.entry_num - 1, 0);
                page_list.entry_num--;
                write_page_list(page_list_paddr, page_list);
            } else {
                // buddy 在同一个页面列表中
                uintptr_t last_entry =
                    read_entry(page_list_paddr, page_list.entry_num - 1);

                if (buddy_entry_index != page_list.entry_num - 1) {
                    write_entry(page_list_paddr, buddy_entry_index, last_entry);
                }
                write_entry(page_list_paddr, page_list.entry_num - 1, 0);
                page_list.entry_num--;
                write_page_list(page_list_paddr, page_list);
            }

            // 合并：选择较小的地址作为新块
            base = (base < buddy_addr) ? base : buddy_addr;
            order++;

            // 更新统计
            zone->free_pages -= (1UL << (order - 1 - MIN_ORDER));

            continue; // 继续尝试更高 order 的合并
        }

        // buddy 不在空闲列表中，停止合并
        break;
    }

    // 将块插入空闲列表
    size_t index = order_to_index(order);
    uintptr_t first_page_list_paddr = alloc->free_area[index];

    if (first_page_list_paddr == 0) {
        // 该 order 还没有页面列表，分配一个
        // 对于 MIN_ORDER，可以使用要释放的块本身
        uintptr_t new_page_paddr;
        if (order == MIN_ORDER) {
            new_page_paddr = base;
        } else {
            // 从 MIN_ORDER 分配一个页面作为元数据
            new_page_paddr = (uintptr_t)early_alloc(DEFAULT_PAGE_SIZE);
            if (new_page_paddr == 0) {
                // 分配失败，丢弃这个块
                return;
            }
        }

        memset((void *)phys_to_virt(new_page_paddr), 0, DEFAULT_PAGE_SIZE);
        page_list_t new_list = {0, 0};
        write_page_list(new_page_paddr, new_list);
        alloc->free_area[index] = new_page_paddr;

        if (new_page_paddr == base) {
            // 使用了要释放的块本身作为元数据页
            return;
        }

        first_page_list_paddr = new_page_paddr;
    }

    page_list_t first_page_list = read_page_list(first_page_list_paddr);

    // 如果第一个页面列表已满，创建新的
    if (first_page_list.entry_num >= BUDDY_ENTRIES) {
        uintptr_t new_page_paddr;
        if (order == MIN_ORDER) {
            new_page_paddr = base;
        } else {
            // 尝试从 buddy 分配
            new_page_paddr = pop_front(alloc, MIN_ORDER);
            if (new_page_paddr == 0) {
                new_page_paddr = (uintptr_t)early_alloc(DEFAULT_PAGE_SIZE);
            }
        }

        if (new_page_paddr == 0) {
            // 无法分配元数据页，丢弃
            return;
        }

        memset((void *)phys_to_virt(new_page_paddr), 0, DEFAULT_PAGE_SIZE);
        page_list_t new_list = {0, first_page_list_paddr};
        write_page_list(new_page_paddr, new_list);
        alloc->free_area[index] = new_page_paddr;

        if (new_page_paddr == base) {
            return;
        }

        first_page_list_paddr = new_page_paddr;
        first_page_list = new_list;
    }

    // 找到有空间的页面列表
    uintptr_t target_paddr = first_page_list_paddr;
    page_list_t target_list = first_page_list;

    if (target_list.entry_num >= BUDDY_ENTRIES && target_list.next_page != 0) {
        uintptr_t second_paddr = target_list.next_page;
        page_list_t second_list = read_page_list(second_paddr);
        if (second_list.entry_num < BUDDY_ENTRIES) {
            target_paddr = second_paddr;
            target_list = second_list;
        }
    }

    if (target_list.entry_num >= BUDDY_ENTRIES) {
        // 不应该发生
        return;
    }

    // 插入条目
    write_entry(target_paddr, target_list.entry_num, base);
    target_list.entry_num++;
    write_page_list(target_paddr, target_list);

    // 更新统计
    zone->free_pages += (1UL << (order - MIN_ORDER));
}

// 从 zone 分配
uintptr_t buddy_alloc_zone(zone_t *zone, size_t count) {
    if (!zone || count == 0)
        return 0;

    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages) + MIN_ORDER;

    if (order >= MAX_ORDER)
        return 0;

    spin_lock(&zone->allocator.lock);
    uintptr_t addr = pop_front(&zone->allocator, order);
    if (addr != 0) {
        zone->free_pages -= required_pages;
    }
    spin_unlock(&zone->allocator.lock);

    return addr;
}

static void init_zone_allocator(zone_t *zone) {
    buddy_allocator_t *alloc = &zone->allocator;

    alloc->lock.lock = 0;

    for (size_t i = 0; i < ORDER_COUNT; i++) {
        // 为每个 order 分配一个初始页面列表
        uintptr_t page_paddr = (uintptr_t)early_alloc(DEFAULT_PAGE_SIZE);
        if (page_paddr == 0) {
            alloc->free_area[i] = 0;
            continue;
        }

        memset((void *)phys_to_virt(page_paddr), 0, DEFAULT_PAGE_SIZE);
        page_list_t list = {0, 0};
        write_page_list(page_paddr, list);
        alloc->free_area[i] = page_paddr;
    }
}

static void init_zone(zone_t *zone, enum zone_type type, uint64_t start_pfn,
                      uint64_t end_pfn) {
    memset(zone, 0, sizeof(zone_t));

    zone->type = type;
    zone->name = zone_names[type];
    zone->zone_start_pfn = start_pfn;
    zone->zone_end_pfn = end_pfn;
    zone->managed_pages = 0;
    zone->free_pages = 0;

    init_zone_allocator(zone);
}

void buddy_init(void) {
    uint64_t max_pfn = memory_size / DEFAULT_PAGE_SIZE;

    uint64_t dma_end_pfn = MIN(max_pfn, ZONE_DMA_END / DEFAULT_PAGE_SIZE);
    uint64_t dma32_end_pfn = MIN(max_pfn, ZONE_DMA32_END / DEFAULT_PAGE_SIZE);

#if defined(__x86_64__)
    // ZONE_DMA
    zones[ZONE_DMA] = (zone_t *)early_alloc(sizeof(zone_t));
    init_zone(zones[ZONE_DMA], ZONE_DMA, 0, dma_end_pfn);
    nr_zones++;

    // ZONE_DMA32
    if (dma_end_pfn < dma32_end_pfn) {
        zones[ZONE_DMA32] = (zone_t *)early_alloc(sizeof(zone_t));
        init_zone(zones[ZONE_DMA32], ZONE_DMA32, dma_end_pfn, dma32_end_pfn);
        nr_zones++;
    }

    // ZONE_NORMAL
    if (dma32_end_pfn < max_pfn) {
        zones[ZONE_NORMAL] = (zone_t *)early_alloc(sizeof(zone_t));
        init_zone(zones[ZONE_NORMAL], ZONE_NORMAL, dma32_end_pfn, max_pfn);
        nr_zones++;
    }
#else
    // ZONE_DMA32
    zones[ZONE_DMA32] = (zone_t *)early_alloc(sizeof(zone_t));
    init_zone(zones[ZONE_DMA32], ZONE_DMA32, 0, dma32_end_pfn);
    nr_zones++;

    // ZONE_NORMAL
    if (dma32_end_pfn < max_pfn) {
        zones[ZONE_NORMAL] = (zone_t *)early_alloc(sizeof(zone_t));
        init_zone(zones[ZONE_NORMAL], ZONE_NORMAL, dma32_end_pfn, max_pfn);
        nr_zones++;
    }
#endif

    void *ptr = early_alloc((max_pfn + 7) / 8);
    bitmap_init(&using_regions, ptr, (max_pfn + 7) / 8);
}

void add_memory_region(uintptr_t start, uintptr_t end, enum zone_type type) {
    zone_t *zone = zones[type];
    if (!zone)
        return;

    // 对齐到页边界
    start = PADDING_UP(start, DEFAULT_PAGE_SIZE);
    end = PADDING_DOWN(end, DEFAULT_PAGE_SIZE);

    if (start >= end)
        return;

    // 确保在 zone 范围内
    uintptr_t zone_start = zone->zone_start_pfn * DEFAULT_PAGE_SIZE;
    uintptr_t zone_end = zone->zone_end_pfn * DEFAULT_PAGE_SIZE;

    if (start < zone_start)
        start = zone_start;
    if (end > zone_end)
        end = zone_end;
    if (start >= end)
        return;

    spin_lock(&zone->allocator.lock);

    uintptr_t paddr = start;
    size_t remain_bytes = end - start;

    // 阶段 1：处理低位对齐（向上对齐到更高 order）
    for (size_t order = MIN_ORDER; order < MAX_ORDER && remain_bytes > 0;
         order++) {
        size_t block_size = 1UL << order;

        if (remain_bytes < block_size)
            break;

        // 检查当前地址是否对齐到下一个 order
        if (order != MAX_ORDER - 1) {
            if ((paddr & (1UL << order)) != 0) {
                // 需要释放一个当前 order 的块来对齐
                buddy_free_zone(zone, paddr, order);
                zone->managed_pages += block_size / DEFAULT_PAGE_SIZE;
                paddr += block_size;
                remain_bytes -= block_size;
            }
        } else {
            // 最高 order，尽可能多地释放
            while (remain_bytes >= block_size) {
                buddy_free_zone(zone, paddr, order);
                zone->managed_pages += block_size / DEFAULT_PAGE_SIZE;
                paddr += block_size;
                remain_bytes -= block_size;
            }
        }
    }

    // 阶段 2：处理剩余字节（从高 order 到低 order）
    for (int order = MAX_ORDER - 1; order >= (int)MIN_ORDER && remain_bytes > 0;
         order--) {
        size_t block_size = 1UL << order;

        if (remain_bytes >= block_size && (paddr & (block_size - 1)) == 0) {
            buddy_free_zone(zone, paddr, order);
            zone->managed_pages += block_size / DEFAULT_PAGE_SIZE;
            paddr += block_size;
            remain_bytes -= block_size;
        }
    }

    spin_unlock(&zone->allocator.lock);
}

uintptr_t alloc_frames(size_t count) {
    if (count == 0)
        return 0;

    uintptr_t addr = 0;

    // 优先尝试 NORMAL zone
    if (zones[ZONE_NORMAL] && zone_has_memory(zones[ZONE_NORMAL])) {
        addr = buddy_alloc_zone(zones[ZONE_NORMAL], count);
        if (addr != 0)
            goto ret;
    }

    // 回退到 DMA32
    if (zones[ZONE_DMA32] && zone_has_memory(zones[ZONE_DMA32])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA32], count);
        if (addr != 0)
            goto ret;
    }

#if defined(__x86_64__)
    // 回退到 DMA
    if (zones[ZONE_DMA] && zone_has_memory(zones[ZONE_DMA])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA], count);
        if (addr != 0)
            goto ret;
    }
#endif

ret:
    bitmap_set_range(&using_regions, addr / DEFAULT_PAGE_SIZE,
                     addr / DEFAULT_PAGE_SIZE + count, true);
    for (uint64_t a = addr; a < (addr + count * DEFAULT_PAGE_SIZE);
         a += DEFAULT_PAGE_SIZE) {
        page_t *p = get_page(a);
        page_ref(p);
    }
    return addr;
}

void free_frames(uintptr_t addr, size_t count) {
    if (addr == 0 || count == 0)
        return;

    uint64_t idx = addr / DEFAULT_PAGE_SIZE;
    for (size_t off = 0; off < count; off++) {
        if (bitmap_get(&using_regions, idx + off) == false)
            return;
        if (bitmap_get(&usable_regions, idx + off) == false)
            return;
    }

    // 确定地址属于哪个 zone
    enum zone_type type = phys_to_zone_type(addr);
    zone_t *zone = zones[type];

    if (!zone)
        return;

    for (uint64_t a = addr; a < (addr + count * DEFAULT_PAGE_SIZE);
         a += DEFAULT_PAGE_SIZE) {
        address_unref(a);
    }
    for (uint64_t a = addr; a < (addr + count * DEFAULT_PAGE_SIZE);
         a += DEFAULT_PAGE_SIZE) {
        if (!address_can_free(a))
            return;
    }

    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages) + MIN_ORDER;

    if (order >= MAX_ORDER)
        order = MAX_ORDER - 1;

    spin_lock(&zone->allocator.lock);
    buddy_free_zone(zone, addr, order);
    bitmap_set_range(&using_regions, idx, idx + count, false);
    spin_unlock(&zone->allocator.lock);
}

uintptr_t alloc_frames_dma32(size_t count) {
    if (count == 0)
        return 0;

    uintptr_t addr = 0;

    // DMA32
    if (zones[ZONE_DMA32] && zone_has_memory(zones[ZONE_DMA32])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA32], count);
        if (addr != 0)
            goto ret;
    }

#if defined(__x86_64__)
    // 回退到 DMA
    if (zones[ZONE_DMA] && zone_has_memory(zones[ZONE_DMA])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA], count);
        if (addr != 0)
            goto ret;
    }
#endif

ret:
    bitmap_set(&usable_regions, addr / DEFAULT_PAGE_SIZE, true);
    return addr;
}

void free_frames_dma32(uintptr_t addr, size_t count) {
    free_frames(addr, count); // 自动识别 zone
}
