#include "arch.h"
#include <mm/mm.h>
#include <libs/klibc.h>

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

uint64_t clone_page_table(uint64_t cr3_old)
{
    uint64_t new = alloc_frames(1);
    copy_page_table_inner(cr3_old, new, 3);
    return new;
}

static void free_page_table_inner(uint64_t phys_addr, int level)
{
    uint64_t *table = (uint64_t *)phys_to_virt(phys_addr);

    for (int i = 0; i < 512; i++)
    {
        uint64_t pte = table[i];
        if (!(pte & ARCH_PT_FLAG_VALID))
            continue;

        if (level == 1)
        {
            free_frames(pte & ARCH_ADDR_MASK, 1);
        }
        else
        {
            free_page_table_inner(pte & ARCH_ADDR_MASK, level - 1); // 递归子页表
        }
    }

    free_frames(phys_addr, 1);
}

void free_page_table(uint64_t directory)
{
    free_page_table_inner(directory, 4);
}

// 内存屏障和TLB操作
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define tlbi(va) asm volatile("tlbi vaae1is, %0" : : "r"((va) >> 12) : "memory")

void arch_flush_tlb(uint64_t vaddr)
{
    dsb(ishst);  // 确保页表写入完成
    tlbi(vaddr); // 无效化单个VA的TLB条目
    dsb(ish);    // 等待TLB操作完成
    isb();       // 流水线同步
}
