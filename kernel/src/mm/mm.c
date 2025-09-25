#include <arch/arch.h>
#include <mm/mm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <drivers/kernel_logger.h>

__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_memmap_request
    memmap_request = {
        .id = LIMINE_MEMMAP_REQUEST,
        .revision = 0,
};

spinlock_t frame_op_lock = {0};

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

uint64_t get_memory_size() {
    uint64_t all_memory_size = 0;
    struct limine_memmap_response *memory_map = memmap_request.response;

    for (uint64_t i = memory_map->entry_count - 1; i > 0; i--) {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE) {
            all_memory_size = region->base + region->length;
            break;
        }
    }

    return all_memory_size;
}

void add_free_region(uintptr_t addr, size_t size);

void frame_init() {
    hhdm_init();

    struct limine_memmap_response *memory_map = memmap_request.response;

    memory_size = get_memory_size();

    size_t bitmap_size = (memory_size / DEFAULT_PAGE_SIZE + 7) / 8;
    uint64_t bitmap_address = 0;

    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE) {
            if (
#if defined(__x86_64__)
                region->base >= 0x100000 &&
#endif
                region->length >= bitmap_size) {
                bitmap_address = region->base;
                break;
            }
        }
    }

    bitmap_init(&usable_regions, (uint8_t *)phys_to_virt(bitmap_address),
                bitmap_size);

    size_t origin_frames = 0;
    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        struct limine_memmap_entry *region = memory_map->entries[i];

        size_t start_frame = region->base / DEFAULT_PAGE_SIZE;
        size_t frame_count = region->length / DEFAULT_PAGE_SIZE;

        if (region->type == LIMINE_MEMMAP_USABLE) {
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

    // for (uint64_t i = 0; i < memory_map->entry_count; i++) {
    //     struct limine_memmap_entry *region = memory_map->entries[i];

    //     if (region->type == LIMINE_MEMMAP_USABLE &&
    //         region->base >= 0x100000000) {

    //         for (uintptr_t paddr = region->base;
    //              paddr < region->base + region->length;
    //              paddr += DEFAULT_PAGE_SIZE) {
    //         next:
    //             uint64_t *pgdir = get_current_page_dir(false);

    //             uint64_t vaddr = phys_to_virt(paddr);

    //             uint64_t indexs[ARCH_MAX_PT_LEVEL] = {0};
    //             for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
    //                 indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    //             }

    //             for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
    //                 uint64_t index = indexs[i];
    //                 uint64_t addr = pgdir[index];
    //                 if (!ARCH_PT_IS_TABLE(addr) || !(addr & ARCH_ADDR_MASK))
    //                 {
    //                     uint64_t a = alloc_frames_early(1);
    //                     memset((uint64_t *)phys_to_virt(a), 0,
    //                            DEFAULT_PAGE_SIZE);
    //                     pgdir[index] = a | ARCH_PT_TABLE_FLAGS;
    //                 }
    //                 if (ARCH_PT_IS_LARGE(addr)) {
    //                     paddr += DEFAULT_PAGE_SIZE;
    //                     if (paddr < region->base + region->length)
    //                         goto next;
    //                     else
    //                         break;
    //                 }
    //                 pgdir =
    //                     (uint64_t *)phys_to_virt(pgdir[index] &
    //                     ARCH_ADDR_MASK);
    //             }

    //             uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];

    //             pgdir[index] = (paddr & ARCH_ADDR_MASK) | PT_FLAG_R |
    //             PT_FLAG_W;

    //             arch_flush_tlb(vaddr);
    //         }
    //     }
    // }

    for (uint64_t i = 0; i < memory_map->entry_count; i++) {
        struct limine_memmap_entry *region = memory_map->entries[i];

        if (region->base < 0x100000)
            continue;

        if (region->type == LIMINE_MEMMAP_USABLE) {
            if (region->base == bitmap_address) {
                add_free_region(
                    (region->base + bitmap_size + DEFAULT_PAGE_SIZE - 1) &
                        ~(DEFAULT_PAGE_SIZE - 1),
                    (region->length - bitmap_size) & ~(DEFAULT_PAGE_SIZE - 1));
            } else {
                add_free_region(region->base, region->length);
            }
        }
    }
}

spinlock_t mem_map_op_lock = {0};

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                    uint64_t size, uint64_t flags) {
    spin_lock(&mem_map_op_lock);

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == 0) {
            uint64_t phys = alloc_frames(1);
            if (phys == (uint64_t)-1) {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags), true);
        } else {
            map_page(pml4, va, paddr + (va - vaddr),
                     get_arch_page_table_flags(flags), true);
        }
    }

    spin_unlock(&mem_map_op_lock);
}

void map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                            uint64_t size, uint64_t flags) {
    spin_lock(&mem_map_op_lock);

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        if (paddr == 0) {
            uint64_t phys = alloc_frames(1);
            if (phys == (uint64_t)-1) {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags), false);
        } else {
            map_page(pml4, va, paddr + (va - vaddr),
                     get_arch_page_table_flags(flags), false);
        }
    }

    spin_unlock(&mem_map_op_lock);
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size) {
    spin_lock(&mem_map_op_lock);

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE) {
        unmap_page(pml4, va);
    }

    spin_unlock(&mem_map_op_lock);
}

uint64_t map_change_attribute(uint64_t *pgdir, uint64_t vaddr, uint64_t flags) {
    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            pgdir[index] &= ~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL);
            pgdir[index] |= flags;
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(
            addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];

    pgdir[index] &= ~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL);
    pgdir[index] |= flags;

    arch_flush_tlb(vaddr);

    return 0;
}

uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags) {
    spin_lock(&mem_map_op_lock);

    for (uint64_t va = vaddr; va < vaddr + len; va += DEFAULT_PAGE_SIZE) {
        map_change_attribute(pgdir, va, get_arch_page_table_flags(flags));
    }

    spin_unlock(&mem_map_op_lock);

    return 0;
}

// 基于 DEFAULT_PAGE_SIZE 的ORDER
#define MAX_ORDER 30 // 最大阶数，支持最大 2^30 * DEFAULT_PAGE_SIZE
#define MIN_ORDER 0  // 最小阶数，单页

// 空闲块结构体 - 直接存储在空闲内存页的开头
typedef struct free_block {
    struct free_block *next; // 链表下一个节点
    struct free_block *prev; // 链表上一个节点
    size_t order;            // 块的阶数 (2^order 个页)
    uint32_t magic;          // 魔数，用于验证
} free_block_t;

#define FREE_BLOCK_MAGIC 0xDEADBEEF

// Buddy分配器结构体
typedef struct {
    free_block_t *free_lists[MAX_ORDER + 1]; // 各阶数的空闲链表头
    uintptr_t base_addr;                     // 内存基地址
    size_t total_size;                       // 总内存大小
} buddy_allocator_t;

static buddy_allocator_t allocator = {0};

// 辅助函数：计算大于等于n的最小2的幂次
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

// 辅助函数：计算log2
static size_t log2_floor(size_t n) {
    size_t log = 0;
    while (n > 1) {
        n >>= 1;
        log++;
    }
    return log;
}

// 辅助函数：获取伙伴块地址
static uintptr_t get_buddy_addr(uintptr_t addr, size_t order) {
    size_t block_size = DEFAULT_PAGE_SIZE << order;
    return addr ^ block_size;
}

// 辅助函数：检查地址是否对齐
static int is_aligned(uintptr_t addr, size_t order) {
    size_t block_size = DEFAULT_PAGE_SIZE << order;
    return (addr & (block_size - 1)) == 0;
}

// 辅助函数：地址转换为free_block指针
static free_block_t *addr_to_block(uintptr_t addr) {
    return (free_block_t *)phys_to_virt(addr);
}

// 辅助函数：free_block指针转换为地址
static uintptr_t block_to_addr(free_block_t *block) {
    return virt_to_phys((uintptr_t)block);
}

// 初始化空闲块
static void init_free_block(uintptr_t addr, size_t order) {
    free_block_t *block = addr_to_block(addr);
    block->next = NULL;
    block->prev = NULL;
    block->order = order;
    block->magic = FREE_BLOCK_MAGIC;
}

// 验证空闲块
static int is_valid_free_block(free_block_t *block) {
    return block && block->magic == FREE_BLOCK_MAGIC;
}

// 从链表中移除块
static void remove_from_list(free_block_t *block, size_t order) {
    if (!is_valid_free_block(block)) {
        return;
    }

    // 从双向链表中移除节点
    if (block->prev) {
        block->prev->next = block->next;
    } else {
        // 当前节点是头节点，更新链表头
        allocator.free_lists[order] = block->next;
    }

    if (block->next) {
        block->next->prev = block->prev;
    }

    memset(block, 0, sizeof(free_block_t));
}

// 添加块到链表头部
static void add_to_list(uintptr_t addr, size_t order) {
    free_block_t *block = addr_to_block(addr);
    init_free_block(addr, order);

    block->next = allocator.free_lists[order];
    block->prev = NULL;

    if (allocator.free_lists[order]) {
        allocator.free_lists[order]->prev = block;
    }

    allocator.free_lists[order] = block;
}

// 在链表中查找指定地址的块
static free_block_t *find_block_in_list(uintptr_t addr, size_t order) {
    free_block_t *current = allocator.free_lists[order];
    while (current) {
        if (!is_valid_free_block(current)) {
            break; // 链表损坏
        }
        if (block_to_addr(current) == addr) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// 分割块
static void split_block(uintptr_t addr, size_t current_order,
                        size_t target_order) {
    while (current_order > target_order) {
        current_order--;
        uintptr_t buddy_addr = addr + (DEFAULT_PAGE_SIZE << current_order);

        // 将伙伴块添加到对应链表
        add_to_list(buddy_addr, current_order);
    }
}

// 添加空闲区域到buddy分配器
void add_free_region(uintptr_t addr, size_t size) {
    printk("Adding free region: addr = %#018lx, size = %#010x\n", addr, size);

    // 确保地址页对齐
    if (addr % DEFAULT_PAGE_SIZE != 0) {
        size_t offset = DEFAULT_PAGE_SIZE - (addr % DEFAULT_PAGE_SIZE);
        addr += offset;
        if (size <= offset)
            return;
        size -= offset;
    }

    // 确保大小是页的整数倍
    size = (size / DEFAULT_PAGE_SIZE) * DEFAULT_PAGE_SIZE;
    if (size == 0)
        return;

    // 设置基地址（第一次添加时）
    if (allocator.base_addr == 0) {
        allocator.base_addr = addr;
    }

    // 将区域按2的幂次大小分解并添加到对应链表
    while (size > 0) {
        // 找到当前地址对齐的最大块大小
        size_t max_size = DEFAULT_PAGE_SIZE;
        size_t order = 0;

        while (order < MAX_ORDER && max_size * 2 <= size &&
               is_aligned(addr, order + 1)) {
            max_size *= 2;
            order++;
        }

        // 添加空闲块到链表
        add_to_list(addr, order);

        addr += max_size;
        size -= max_size;
        allocator.total_size += max_size;
    }
}

// 分配页框
uintptr_t alloc_frames(size_t count) {
    if (count == 0)
        return (uintptr_t)-1;

    spin_lock(&frame_op_lock);

    // 计算需要的阶数（向上取整到2的幂次）
    size_t required_pages = next_power_of_2(count);
    size_t order = log2_floor(required_pages);

    // 从当前阶数开始查找可用块
    size_t search_order = order;
    while (search_order <= MAX_ORDER && !allocator.free_lists[search_order]) {
        search_order++;
    }

    if (search_order > MAX_ORDER) {
        printk("Buddy: count too big!!!\n");
        spin_unlock(&frame_op_lock);
        // 没有足够大的块
        return (uintptr_t)-1;
    }

    // 取出块
    free_block_t *block = allocator.free_lists[search_order];
    if (!is_valid_free_block(block)) {
        printk("Buddy: block metadata was broken!!!\n");
        spin_unlock(&frame_op_lock);
        return (uintptr_t)-1; // 链表损坏
    }

    uintptr_t allocated_addr = block_to_addr(block);
    size_t allocated_order = block->order;

    remove_from_list(block, search_order);

    // 如果块太大，分割它
    if (allocated_order > order) {
        split_block(allocated_addr, allocated_order, order);
    }

    spin_unlock(&frame_op_lock);
    return allocated_addr;
}

// 释放页框
void free_frames(uintptr_t addr, size_t count) {
    if (count == 0 || addr == 0)
        return;

    spin_lock(&frame_op_lock);

    // 确保地址页对齐
    if (addr % DEFAULT_PAGE_SIZE != 0) {
        spin_unlock(&frame_op_lock);
        return; // 地址未页对齐
    }

    size_t idx = addr / DEFAULT_PAGE_SIZE;
    if (bitmap_get(&usable_regions, idx) == false) {
        spin_unlock(&frame_op_lock);
        return;
    }

    // 将要释放的区域按2的幂次大小分解
    size_t remaining = count;
    uintptr_t current_addr = addr;

    while (remaining > 0) {
        // 找到当前地址对齐的最大块大小
        size_t max_pages = 1;
        size_t order = 0;

        while (order < MAX_ORDER && max_pages * 2 <= remaining &&
               is_aligned(current_addr, order + 1)) {
            max_pages *= 2;
            order++;
        }

        // 尝试合并伙伴块
        while (order < MAX_ORDER) {
            uintptr_t buddy_addr = get_buddy_addr(current_addr, order);
            free_block_t *buddy = find_block_in_list(buddy_addr, order);

            if (!buddy)
                break; // 伙伴不存在或不空闲

            // 移除伙伴块
            remove_from_list(buddy, order);

            // 合并：使用较小的地址作为合并后的块地址
            if (buddy_addr < current_addr) {
                current_addr = buddy_addr;
            }

            order++;
        }

        // 添加释放的块到链表
        add_to_list(current_addr, order);

        size_t freed_pages = 1 << order;
        current_addr += freed_pages * DEFAULT_PAGE_SIZE;
        if (remaining <= freed_pages) {
            break;
        }
        remaining -= freed_pages;
    }

    spin_unlock(&frame_op_lock);
}

// 获取空闲页数统计
size_t get_free_pages_count() {
    size_t total = 0;
    for (int order = 0; order <= MAX_ORDER; order++) {
        size_t count = 0;
        free_block_t *current = allocator.free_lists[order];
        while (current) {
            if (!is_valid_free_block(current)) {
                break; // 链表损坏
            }
            count++;
            current = current->next;
        }
        total += count * (1 << order);
    }
    return total;
}
