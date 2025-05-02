#include <arch/aarch64/mm/page_table.h>
#include <mm/mm.h>

// 合成页表项属性
uint64_t get_arch_page_table_flags(uint64_t flags)
{
    uint64_t attr = ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_4K_PAGE | ARCH_PT_FLAG_INNER_SH | ARCH_PT_FLAG_ACCESS | ARCH_PT_FLAG_WB;

    if ((flags & PT_FLAG_W) == 0)
        attr |= ARCH_PT_FLAG_READONLY;
    if ((flags & PT_FLAG_X) == 0)
        attr |= ARCH_PT_FLAG_XN;
    if (flags & PT_FLAG_U)
        attr |= ARCH_PT_FLAG_USER;

    return attr;
}

uint64_t *get_kernel_page_dir()
{
    return NULL;
}

// 内存屏障和TLB操作
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define tlbi(va) asm volatile("tlbi vaae1is, %0" : : "r"((va) >> 12) : "memory")

// 映射虚拟地址到物理地址
void map_page(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t flags)
{
    uint64_t indices[] = {
        (vaddr >> 39) & 0x1FF, // PML4索引
        (vaddr >> 30) & 0x1FF, // PDPT索引
        (vaddr >> 21) & 0x1FF, // PD索引
        (vaddr >> 12) & 0x1FF  // PT索引
    };

    uint64_t *current_table = pml4;

    // 遍历PML4, PDPT, PD
    for (int level = 0; level < 3; ++level)
    {
        uint64_t index = indices[level];
        uint64_t *entry = &current_table[index];

        if (!(*entry & ARCH_PT_FLAG_VALID))
        {
            uint64_t new_phys = alloc_frames(1);
            uint64_t *new_table = phys_to_virt((uint64_t *)new_phys);
            memset(new_table, 0, 4096);
            *entry = new_phys | ARCH_PT_TABLE_FLAGS;
        }

        uint64_t next_table_phys = *entry & ARCH_ADDR_MASK;
        current_table = phys_to_virt((uint64_t *)next_table_phys);
    }

    // 处理PTE
    uint64_t pt_index = indices[3];
    uint64_t *pte = &current_table[pt_index];
    if (!(*pte & ARCH_PT_FLAG_VALID))
    {
        *pte = (paddr & ARCH_ADDR_MASK) | flags;
    }

    dsb(ishst);  // 确保页表写入完成
    tlbi(vaddr); // 无效化单个VA的TLB条目
    dsb(ish);    // 等待TLB操作完成
    isb();       // 流水线同步
}

// 释放虚拟地址映射并回收页表
void unmap_page(uint64_t *pml4, uint64_t vaddr)
{
    uint64_t *tables[4]; // 保存各级页表指针
    uint64_t indices[4] = {
        (vaddr >> 39) & 0x1FF,
        (vaddr >> 30) & 0x1FF,
        (vaddr >> 21) & 0x1FF,
        (vaddr >> 12) & 0x1FF};

    // 获取各级页表
    uint64_t *current = pml4;
    for (int level = 0; level < 4; ++level)
    {
        tables[level] = current;
        if (level < 3)
        {
            uint64_t entry = current[indices[level]];
            if (!(entry & ARCH_PT_FLAG_VALID))
                return; // 页表不存在
            current = (uint64_t *)phys_to_virt(entry & ARCH_ADDR_MASK);
        }
    }

    // 清除PTE并释放物理页
    uint64_t *pte = &tables[3][indices[3]];
    if (*pte & ARCH_PT_FLAG_VALID)
    {
        free_frames(*pte & ARCH_ADDR_MASK, 1);
        *pte = 0;
    }

    // 自底向上回收空闲页表
    for (int level = 3; level > 0; --level)
    {
        uint64_t *table = tables[level - 1];
        uint64_t index = indices[level - 1];
        uint64_t *entry = &table[index];

        // 检查当前页表是否全空
        bool used = false;
        uint64_t *check_table = (uint64_t *)phys_to_virt(*entry & ARCH_ADDR_MASK);
        for (int i = 0; i < 512; ++i)
        {
            if (PT_IS_TABLE(check_table[i]))
            {
                used = true;
                break;
            }
        }

        if (!used)
        {
            free_frames(*entry & ARCH_ADDR_MASK, 1);
            *entry = 0; // 清除上级条目
        }
        else
        {
            break; // 上层页表仍在使用，停止回收
        }
    }

    dsb(ishst);  // 确保页表写入完成
    tlbi(vaddr); // 无效化单个VA的TLB条目
    dsb(ish);    // 等待TLB操作完成
    isb();       // 流水线同步
}

uint64_t *get_current_page_dir(bool user)
{
    uint64_t page_table_base = 0;
    if (user)
    {
        uint64_t ttbr0_el1 = 0;
        asm volatile("mrs %0, TTBR0_EL1" : "=r"(ttbr0_el1));
        page_table_base = ttbr0_el1 & 0xFFFFFFFFFFF0;
    }
    else
    {
        uint64_t ttbr0_el1 = 0;
        asm volatile("mrs %0, TTBR1_EL1" : "=r"(ttbr0_el1));
        page_table_base = ttbr0_el1 & 0xFFFFFFFFFFF0;
    }
    return (uint64_t *)phys_to_virt(page_table_base);
}

static void copy_page_table_inner(uint64_t src_phys, uint64_t dst_phys, int level)
{
    void *src = (void *)phys_to_virt(src_phys);
    void *dst = (void *)phys_to_virt(dst_phys);

    // 复制当前页表内容
    memcpy(dst, src, DEFAULT_PAGE_SIZE);

    // 如果是中间层（非叶子节点），递归处理下一级
    if (level > 0)
    {
        for (int i = 0; i < (1 << 9); i++)
        {
            uint64_t *entry = (uint64_t *)src + i;
            if (*entry & ARCH_PT_FLAG_VALID)
            {
                // 提取下一级页表物理地址
                uint64_t next_src_phys = *entry & ARCH_ADDR_MASK;

                // 分配新物理帧并递归拷贝
                uint64_t next_dst_phys = alloc_frames(1);
                copy_page_table_inner(next_src_phys, next_dst_phys, level - 1);

                // 更新目标页表项（保留原标志位）
                uint64_t *dst_entry = (uint64_t *)dst + i;
                *dst_entry = next_dst_phys | (*entry & ~ARCH_ADDR_MASK);
            }
        }
    }
}

uint64_t clone_page_table(uint64_t cr3_old, uint64_t user_stack_start, uint64_t user_stack_end)
{
    uint64_t new = alloc_frames(1);
    copy_page_table_inner(cr3_old, new, 3);
    return new;
}

void free_page_table(uint64_t directory)
{
}
