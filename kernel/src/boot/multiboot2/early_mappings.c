#include <libs/klibc.h>
#include <boot/multiboot2/multiboot2_header.h>
#include <arch/arch.h>

// 内存布局定义
#define KERNEL_VMA_BASE 0xFFFFFFFF80000000UL // 内核虚拟地址基址
#define HHDM_BASE 0xFFFF800000000000UL       // HHDM基址
#define LOW_MEMORY_BASE 0x0000000000000000UL // 低地址基址

// 地址转换宏
#define PHYS_TO_VIRT(addr) ((addr) + HHDM_BASE)
#define VIRT_TO_PHYS(addr) ((addr) - HHDM_BASE)
#define KERNEL_PHYS_TO_VIRT(addr) ((addr) + KERNEL_VMA_BASE)

// 页表项标志
#define PAGE_PRESENT (1UL << 0)
#define PAGE_WRITABLE (1UL << 1)
#define PAGE_USER (1UL << 2)
#define PAGE_SIZE (1UL << 7) // 用于2MB页面

// 页面大小定义
#define PAGE_SIZE_4K 4096
#define PAGE_SIZE_2M (2 * 1024 * 1024)
#define PAGE_SIZE_1G (1024 * 1024 * 1024)

// 页表级别
#define PML4_INDEX(addr) (((addr) >> 39) & 0x1FF)
#define PDPT_INDEX(addr) (((addr) >> 30) & 0x1FF)
#define PD_INDEX(addr) (((addr) >> 21) & 0x1FF)
#define PT_INDEX(addr) (((addr) >> 12) & 0x1FF)

// 内存区域结构
#define MAX_MEMORY_REGIONS 64

struct memory_region {
    uint64_t start;
    uint64_t size;
    uint32_t type;
    bool available;
};

// 物理内存分配器结构
struct physical_allocator {
    uint64_t current_addr; // 当前分配位置
    uint64_t region_end;   // 当前区域结束位置
    int current_region;    // 当前使用的内存区域索引
};

// 外部变量声明
uint32_t multiboot_magic;
uint64_t multiboot_info;
uint64_t kernel_phys_start;
uint64_t kernel_phys_end;

// 全局变量
struct memory_region memory_regions[MAX_MEMORY_REGIONS];
int memory_region_count = 0;
struct physical_allocator phys_allocator = {0};

// 内核物理地址范围 (由链接器提供)
extern uint64_t kernel_virt_start;
extern uint64_t kernel_virt_end;
extern uint64_t kernel_phys_start;
extern uint64_t kernel_phys_end;

// 获取内核物理地址范围
uint64_t get_kernel_phys_start(void) { return (uint64_t)&kernel_phys_start; }

uint64_t get_kernel_phys_end(void) {
    return ((uint64_t)&kernel_phys_end + PAGE_SIZE_4K - 1) &
           ~(PAGE_SIZE_4K - 1);
}

// 初始化物理内存分配器
void init_physical_allocator(void) {
    uint64_t kernel_start_addr = get_kernel_phys_start();
    uint64_t kernel_end_addr = get_kernel_phys_end();

    // 找到第一个可用的内存区域（不与内核重叠且在4MB之后）
    for (int i = 0; i < memory_region_count; i++) {
        if (memory_regions[i].type == MULTIBOOT_MEMORY_AVAILABLE) {
            uint64_t region_start = memory_regions[i].start;
            uint64_t region_end = region_start + memory_regions[i].size;

            // 确保区域在4MB之后且不与内核重叠
            if (region_start < 4 * 1024 * 1024) {
                region_start = 4 * 1024 * 1024;
            }

            if (region_start >= region_end)
                continue;

            // 检查是否与内核重叠
            if (region_end <= kernel_start_addr ||
                region_start >= kernel_end_addr) {
                // 区域不与内核重叠
                phys_allocator.current_addr = region_start;
                phys_allocator.region_end = region_end;
                phys_allocator.current_region = i;

                return;
            } else if (region_start < kernel_start_addr &&
                       region_end > kernel_end_addr) {
                // 内核在区域中间，使用内核后面的部分
                phys_allocator.current_addr = kernel_end_addr;
                phys_allocator.region_end = region_end;
                phys_allocator.current_region = i;

                return;
            }
        }
    }
}

// 分配一个物理页面
uint64_t allocate_physical_page(void) {
    // 对齐到4KB边界
    phys_allocator.current_addr =
        (phys_allocator.current_addr + PAGE_SIZE_4K - 1) & ~(PAGE_SIZE_4K - 1);

    // 检查当前区域是否还有空间
    if (phys_allocator.current_addr + PAGE_SIZE_4K >
        phys_allocator.region_end) {
        // 寻找下一个可用区域
        for (int i = phys_allocator.current_region + 1; i < memory_region_count;
             i++) {
            if (memory_regions[i].type == MULTIBOOT_MEMORY_AVAILABLE) {
                uint64_t kernel_start_addr = get_kernel_phys_start();
                uint64_t kernel_end_addr = get_kernel_phys_end();
                uint64_t region_start = memory_regions[i].start;
                uint64_t region_end = region_start + memory_regions[i].size;

                // 检查是否与内核重叠
                if (region_end <= kernel_start_addr ||
                    region_start >= kernel_end_addr) {
                    phys_allocator.current_addr = region_start;
                    phys_allocator.region_end = region_end;
                    phys_allocator.current_region = i;
                    break;
                } else if (region_start < kernel_start_addr &&
                           region_end > kernel_end_addr) {
                    phys_allocator.current_addr = kernel_end_addr;
                    phys_allocator.region_end = region_end;
                    phys_allocator.current_region = i;
                    break;
                }
            }
        }

        // 再次对齐
        phys_allocator.current_addr =
            (phys_allocator.current_addr + PAGE_SIZE_4K - 1) &
            ~(PAGE_SIZE_4K - 1);

        if (phys_allocator.current_addr + PAGE_SIZE_4K >
            phys_allocator.region_end) {
            return 0;
        }
    }

    uint64_t addr = phys_allocator.current_addr;
    phys_allocator.current_addr += PAGE_SIZE_4K;

    return addr;
}

// 分配并清空新的页表 (返回虚拟地址)
uint64_t *allocate_page_table(void) {
    uint64_t phys_addr = allocate_physical_page();
    if (phys_addr == 0) {
        return (uint64_t *)0;
    }

    // 通过HHDM访问物理页面
    uint64_t *table = (uint64_t *)PHYS_TO_VIRT(phys_addr);

    // 清空页表
    for (int i = 0; i < 512; i++) {
        table[i] = 0;
    }

    return table;
}

// 设置CR3寄存器
void set_cr3(uint64_t cr3) {
    asm volatile("mov %0, %%cr3" ::"r"(cr3) : "memory");
}

// 映射内存区域
void map_memory_region(uint64_t virt_addr, uint64_t phys_addr, uint64_t size) {
    uint64_t cr3 = get_cr3();
    uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRT(cr3 & ~0xFFF);

    // 按2MB页面对齐
    virt_addr &= ~(PAGE_SIZE_2M - 1);
    phys_addr &= ~(PAGE_SIZE_2M - 1);
    size = (size + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);

    for (uint64_t offset = 0; offset < size; offset += PAGE_SIZE_2M) {
        uint64_t va = virt_addr + offset;
        uint64_t pa = phys_addr + offset;

        // 获取页表索引
        uint64_t pml4_idx = PML4_INDEX(va);
        uint64_t pdpt_idx = PDPT_INDEX(va);
        uint64_t pd_idx = PD_INDEX(va);

        // 检查PML4条目
        if (!(pml4[pml4_idx] & PAGE_PRESENT)) {
            uint64_t *pdpt = allocate_page_table();
            if (pdpt == (uint64_t *)0) {
                return;
            }
            pml4[pml4_idx] =
                VIRT_TO_PHYS((uint64_t)pdpt) | PAGE_PRESENT | PAGE_WRITABLE;
        }

        // 获取PDPT
        uint64_t *pdpt = (uint64_t *)PHYS_TO_VIRT(pml4[pml4_idx] & ~0xFFF);

        // 检查PDPT条目
        if (!(pdpt[pdpt_idx] & PAGE_PRESENT)) {
            uint64_t *pd = allocate_page_table();
            if (pd == (uint64_t *)0) {
                return;
            }
            pdpt[pdpt_idx] =
                VIRT_TO_PHYS((uint64_t)pd) | PAGE_PRESENT | PAGE_WRITABLE;
        }

        // 获取页目录
        uint64_t *pd = (uint64_t *)PHYS_TO_VIRT(pdpt[pdpt_idx] & ~0xFFF);

        // 设置2MB页面
        pd[pd_idx] = pa | PAGE_PRESENT | PAGE_WRITABLE | PAGE_SIZE;
    }

    // 刷新TLB
    set_cr3(cr3);
}

// 移除低地址映射
void remove_low_mappings(void) {
    uint64_t cr3 = get_cr3();
    uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRT(cr3 & ~0xFFF);

    // 移除PML4[0] (低地址映射)
    pml4[0] = 0;

    // 刷新TLB
    set_cr3(cr3);
}

// 解析multiboot2内存映射
void parse_multiboot_memory_map(void) {
    // multiboot_info现在是物理地址，需要通过HHDM访问
    uint64_t mbi_addr = PHYS_TO_VIRT(multiboot_info);
    uint32_t total_size = *(uint32_t *)mbi_addr;

    struct multiboot_tag *tag = (struct multiboot_tag *)(mbi_addr + 8);
    memory_region_count = 0;

    while ((uint64_t)tag < mbi_addr + total_size &&
           memory_region_count < MAX_MEMORY_REGIONS) {
        if (tag->type == 0)
            break; // 结束标签

        if (tag->type == 6) { // 内存映射标签
            struct multiboot_tag_mmap *mmap_tag =
                (struct multiboot_tag_mmap *)tag;
            struct multiboot_mmap_entry *entry =
                (struct multiboot_mmap_entry *)((uint64_t)mmap_tag +
                                                sizeof(*mmap_tag));

            while ((uint64_t)entry < (uint64_t)tag + tag->size &&
                   memory_region_count < MAX_MEMORY_REGIONS) {
                // 保存内存区域信息
                memory_regions[memory_region_count].start = entry->addr;
                memory_regions[memory_region_count].size = entry->len;
                memory_regions[memory_region_count].type = entry->type;
                memory_regions[memory_region_count].available =
                    (entry->type == MULTIBOOT_MEMORY_AVAILABLE);

                memory_region_count++;
                entry = (struct multiboot_mmap_entry *)((uint64_t)entry +
                                                        mmap_tag->entry_size);
            }
            break;
        }

        // 移动到下一个标签
        tag = (struct multiboot_tag *)((uint64_t)tag + ((tag->size + 7) & ~7));
    }
}

// 扩展HHDM映射到所有可用内存
void extend_hhdm_mapping(void) {
    uint64_t total_mapped = 0;

    for (int i = 0; i < memory_region_count; i++) {
        if (memory_regions[i].type == MULTIBOOT_MEMORY_AVAILABLE) {
            uint64_t start = memory_regions[i].start;
            uint64_t size = memory_regions[i].size;
            uint64_t hhdm_start = HHDM_BASE + start;

            // 检查是否已经在启动时映射了（前128GB）
            if (start < 128UL * 1024 * 1024 * 1024) {
                uint64_t already_mapped = 128UL * 1024 * 1024 * 1024 - start;
                if (already_mapped >= size) {
                    continue; // 整个区域已映射
                }
                // 只映射未映射的部分
                start += already_mapped;
                size -= already_mapped;
                hhdm_start += already_mapped;
            }

            if (size > 0) {
                map_memory_region(hhdm_start, start, size);
                total_mapped += size;
            }
        }
    }
}

void setup_early_mappings(uint32_t magic, uint64_t info) { // 解析内存映射
    multiboot_magic = magic;
    multiboot_info = PHYS_TO_VIRT(info);

    parse_multiboot_memory_map();

    // 初始化物理内存分配器
    init_physical_allocator();

    // 扩展HHDM映射
    extend_hhdm_mapping();

    // 移除低地址映射（现在不再需要）
    remove_low_mappings();

    asm volatile("jmp _start");
}
