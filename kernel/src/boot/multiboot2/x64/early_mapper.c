#include <libs/klibc.h>
#include <boot/multiboot2/x64/multiboot2.h>
#include <boot/boot.h>

#define PAGE_SIZE_4K 0x1000   // 4KB
#define PAGE_SIZE_2M 0x200000 // 2MB

// 页表项标志位
#define PTE_PRESENT (1ULL << 0) // P位
#define PTE_WRITE (1ULL << 1)   // R/W位
#define PTE_PS (1ULL << 7)      // 页大小位 (2M页)

typedef uint64_t pte_t;

static uint8_t *g_page_alloc_base = NULL;
static uint64_t g_page_alloc_offset = 0;
static uint64_t g_page_alloc_size = 0;

// 初始化页表分配器
static void init_page_allocator(uint64_t base, uint64_t size) {
    g_page_alloc_base = (uint8_t *)base;
    g_page_alloc_offset = 0;
    g_page_alloc_size = size;
}

// 分配一个4K页表并清零
static void *alloc_page_table(void) {
    if (g_page_alloc_offset + PAGE_SIZE_4K > g_page_alloc_size) {
        return NULL;
    }

    void *page = g_page_alloc_base + g_page_alloc_offset;
    g_page_alloc_offset += PAGE_SIZE_4K;

    // 清零页表
    uint64_t *p = (uint64_t *)(page + 0xffff800000000000);
    for (int i = 0; i < 512; i++) {
        p[i] = 0;
    }

    return page;
}

// 获取已使用的内存大小
static uint64_t get_allocated_size(void) { return g_page_alloc_offset; }

static struct multiboot_tag *next_tag(struct multiboot_tag *tag) {
    uint8_t *addr = (uint8_t *)tag;
    addr += ((tag->size + 7) & ~7); // 8字节对齐
    return (struct multiboot_tag *)addr;
}

static struct multiboot_tag_mmap *find_mmap_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_MMAP) {
            return (struct multiboot_tag_mmap *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

static struct multiboot_tag_framebuffer *
find_framebuffer_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_FRAMEBUFFER) {
            return (void *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

// ==================== 内存统计函数 ====================
// 统计可用内存的最高地址
static uint64_t
calculate_max_memory_address(struct multiboot_tag_mmap *mmap_tag) {
    uint64_t max_addr = 0;

    struct multiboot_mmap_entry *entries =
        (struct multiboot_mmap_entry *)((uint8_t *)mmap_tag +
                                        sizeof(struct multiboot_tag_mmap));

    uint32_t num_entries =
        (mmap_tag->size - sizeof(struct multiboot_tag_mmap)) /
        mmap_tag->entry_size;

    for (uint32_t i = 0; i < num_entries; i++) {
        struct multiboot_mmap_entry *entry =
            (struct multiboot_mmap_entry *)((uint8_t *)entries +
                                            i * mmap_tag->entry_size);

        if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
            uint64_t end_addr = entry->addr + entry->len;
            if (end_addr > max_addr) {
                max_addr = end_addr;
            }
        }
    }

    return max_addr;
}

// 计算映射所需的页表数量
static uint64_t calculate_page_tables_needed(uint64_t max_memory) {
    // 计算需要多少个2M页
    uint64_t num_2m_pages = (max_memory + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;

    // 计算需要的PD数量 (每个PD有512个项，每项映射2M)
    // 每个PD可以映射 512 * 2M = 1GB
    uint64_t num_pd = (num_2m_pages + 511) / 512;

    // 计算需要的PDPT数量 (每个PDPT有512个项，每项指向一个PD)
    // 每个PDPT可以映射 512GB
    uint64_t num_pdpt = (num_pd + 511) / 512;

    // PML4只需要1个
    uint64_t num_pml4 = 1;

    // 总数
    return num_pml4 + num_pdpt + num_pd;
}

// 查找足够大的内存区域
static uint64_t find_suitable_region(struct multiboot_tag_mmap *mmap_tag,
                                     uint64_t required_size) {
    struct multiboot_mmap_entry *entries =
        (struct multiboot_mmap_entry *)((uint8_t *)mmap_tag +
                                        sizeof(struct multiboot_tag_mmap));

    uint32_t num_entries =
        (mmap_tag->size - sizeof(struct multiboot_tag_mmap)) /
        mmap_tag->entry_size;

    // 寻找高地址的可用区域，避免覆盖低地址的重要数据
    uint64_t best_addr = 0;

    for (uint32_t i = 0; i < num_entries; i++) {
        struct multiboot_mmap_entry *entry =
            (struct multiboot_mmap_entry *)((uint8_t *)entries +
                                            i * mmap_tag->entry_size);

        if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
            // 对齐到4K边界
            uint64_t aligned_addr = (entry->addr + PAGE_SIZE_4K - 1) &
                                    ~(uint64_t)(PAGE_SIZE_4K - 1);
            uint64_t aligned_end = entry->addr + entry->len;
            uint64_t available_size = aligned_end - aligned_addr;

            if (aligned_addr > 0x6400000) {
                break;
            }

            if (available_size >= required_size && aligned_addr > best_addr) {
                best_addr = aligned_addr;
            }
        }
    }

    return best_addr;
}

// ==================== 页表映射函数 ====================
// 获取或创建PDPT
static pte_t *get_or_create_pdpt(pte_t *pml4, uint64_t vaddr) {
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;

    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        pte_t *pdpt = (pte_t *)alloc_page_table();
        if (!pdpt)
            return NULL;

        pml4[pml4_idx] = ((uint64_t)pdpt) | PTE_PRESENT | PTE_WRITE;
    }

    return (pte_t *)(pml4[pml4_idx] & ~0xFFFULL);
}

// 获取或创建PD
static pte_t *get_or_create_pd(pte_t *pdpt, uint64_t vaddr) {
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;

    if (!(pdpt[pdpt_idx] & PTE_PRESENT)) {
        pte_t *pd = (pte_t *)alloc_page_table();
        if (!pd)
            return NULL;

        pdpt[pdpt_idx] = ((uint64_t)pd) | PTE_PRESENT | PTE_WRITE;
    }

    return (pte_t *)(pdpt[pdpt_idx] & ~0xFFFULL);
}

// 映射一个2M页面 (恒等映射: vaddr = paddr)
static int map_2m_page(pte_t *pml4, uint64_t paddr) {
    uint64_t vaddr = paddr + 0xffff800000000000; // 偏移映射

    // 地址必须2M对齐
    if (paddr & (PAGE_SIZE_2M - 1)) {
        return -1;
    }

    pte_t *pdpt = get_or_create_pdpt(pml4, vaddr);
    if (!pdpt)
        return -1;

    pte_t *pd = get_or_create_pd(pdpt, vaddr);
    if (!pd)
        return -1;

    uint64_t pd_idx = (vaddr >> 21) & 0x1FF;
    pd[pd_idx] = (paddr & ~0x1FFFFFULL) | PTE_PRESENT | PTE_WRITE | PTE_PS;

    return 0;
}

// 映射一段内存区域
static int map_memory_region(pte_t *pml4, uint64_t base, uint64_t size) {
    // 向下对齐起始地址
    uint64_t start = base & ~(uint64_t)(PAGE_SIZE_2M - 1);
    // 向上对齐结束地址
    uint64_t end =
        (base + size + PAGE_SIZE_2M - 1) & ~(uint64_t)(PAGE_SIZE_2M - 1);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE_2M) {
        if (map_2m_page(pml4, addr) != 0) {
            return -1;
        }
    }

    return 0;
}

extern boot_memory_map_t multiboot2_memory_map;

extern uint8_t kernel_phys_start[], kernel_phys_end[];

int setup_2m_page_tables(void *mb2_info_addr, pte_t **out_pml4) {
    // 步骤1: 查找Memory Map标签
    struct multiboot_tag_mmap *mmap_tag = find_mmap_tag(mb2_info_addr);
    if (!mmap_tag) {
        return -1; // 找不到memory map
    }

    // 步骤2: 计算需要映射的最大内存地址
    uint64_t max_memory = calculate_max_memory_address(mmap_tag);
    if (max_memory == 0) {
        return -2; // 没有可用内存
    }

    // 步骤3: 计算所需的页表数量和大小
    uint64_t pages_needed = calculate_page_tables_needed(max_memory);
    uint64_t required_size = pages_needed * PAGE_SIZE_4K;

    // 步骤4: 查找合适的内存区域
    uint64_t alloc_base = find_suitable_region(mmap_tag, required_size);
    if (alloc_base == 0) {
        return -3; // 找不到足够大的内存区域
    }

    // 步骤5: 初始化页表分配器
    init_page_allocator(alloc_base, required_size);

    // 步骤6: 创建根页表 (PML4)
    pte_t *pml4 = (pte_t *)alloc_page_table();
    if (!pml4) {
        return -4; // 分配PML4失败
    }

    // 步骤7: 映射所有可用内存区域
    struct multiboot_mmap_entry *entries = mmap_tag->entries;

    while ((uint64_t)entries < (uint64_t)mmap_tag + mmap_tag->size) {
        struct multiboot_mmap_entry *entry = entries;

        if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
            if (map_memory_region(pml4, entry->addr, entry->len) != 0) {
                return -5; // 映射失败
            }
        }

        entries++;
    }

    uint64_t kpstart = ((uint64_t)&kernel_phys_start) & ~(PAGE_SIZE_2M - 1);
    uint64_t kpend =
        ((uint64_t)&kernel_phys_end + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);

    map_memory_region(pml4, kpstart, kpend - kpstart);

    struct multiboot_tag_framebuffer *fb_tag =
        find_framebuffer_tag(mb2_info_addr);

    for (uint64_t i = 0; i < (fb_tag->common.framebuffer_pitch *
                                  fb_tag->common.framebuffer_height +
                              PAGE_SIZE_2M - 1) /
                                 PAGE_SIZE_2M;
         i++) {
        if (map_2m_page(pml4, fb_tag->common.framebuffer_addr +
                                  i * PAGE_SIZE_2M) != 0) {
            return -6;
        }
    }

    // 步骤8: 标记页表占用的内存为不可用
    uint64_t actual_used = get_allocated_size();
    uint64_t alloc_end = alloc_base + actual_used;

    multiboot2_memory_map.entry_count = 0;

    entries = mmap_tag->entries;

    while ((uint64_t)entries < (uint64_t)mmap_tag + mmap_tag->size) {
        struct multiboot_mmap_entry *entry = entries;

        if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
            uint64_t entry_start = entry->addr;
            uint64_t entry_end = entry->addr + entry->len;
            uint64_t alloc_end = alloc_base + g_page_alloc_size;

#define ADD_REGION(start, end, region_type)                                    \
    if ((end) > (start)) {                                                     \
        multiboot2_memory_map.entries[multiboot2_memory_map.entry_count]       \
            .addr = (start);                                                   \
        multiboot2_memory_map.entries[multiboot2_memory_map.entry_count].len = \
            (end) - (start);                                                   \
        multiboot2_memory_map.entries[multiboot2_memory_map.entry_count]       \
            .type = (region_type);                                             \
        multiboot2_memory_map.entry_count++;                                   \
    }

            uint64_t pos = entry_start;

            // 按顺序处理各个区域
            while (pos < entry_end) {
                // 检查当前位置是否在kernel区域
                if (pos >= kpstart && pos < kpend) {
                    // 在kernel区域内，添加RESERVED区域
                    uint64_t reserved_end =
                        (kpend < entry_end) ? kpend : entry_end;
                    ADD_REGION(pos, reserved_end, RESERVED);
                    pos = reserved_end;
                }
                // 检查当前位置是否在页表分配区域
                else if (pos >= alloc_base && pos < alloc_end) {
                    // 在页表区域内，添加RESERVED区域
                    uint64_t reserved_end =
                        (alloc_end < entry_end) ? alloc_end : entry_end;
                    ADD_REGION(pos, reserved_end, RESERVED);
                    pos = reserved_end;
                }
                // 当前位置是可用区域
                else {
                    // 计算下一个保留区域的起始位置
                    uint64_t next_reserved = entry_end;

                    if (kpstart > pos && kpstart < entry_end &&
                        kpstart < next_reserved) {
                        next_reserved = kpstart;
                    }
                    if (alloc_base > pos && alloc_base < entry_end &&
                        alloc_base < next_reserved) {
                        next_reserved = alloc_base;
                    }

                    ADD_REGION(pos, next_reserved, USABLE);
                    pos = next_reserved;
                }
            }
        } else {
            // 非AVAILABLE类型，直接标记为RESERVED
            ADD_REGION(entry->addr, entry->len, RESERVED);
        }

#undef ADD_REGION

        entries++;
    }

    // 步骤9: 返回PML4地址
    *out_pml4 = pml4;

    return 0;
}
