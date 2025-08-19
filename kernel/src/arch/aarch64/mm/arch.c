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

// 内存屏障和TLB操作
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define tlbi(va) asm volatile("tlbi vale1, %0" : : "r"(va) : "memory")

void arch_flush_tlb(uint64_t vaddr)
{
    uint64_t va = (vaddr >> 12) & 0x3FFFFFFFFF;

    dsb(ishst); // 确保页表写入完成
    tlbi(va);   // 无效化单个VA的TLB条目
    dsb(ish);   // 等待TLB操作完成
    isb();      // 流水线同步
}
