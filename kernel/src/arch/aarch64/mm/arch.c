#include "arch.h"
#include <mm/mm.h>
#include <libs/klibc.h>

// AArch64内存属性定义
#define MAIR_ATTR_DEVICE_nGnRnE 0x00 // 设备内存，无聚集，无重排序，无早期确认
#define MAIR_ATTR_DEVICE_nGnRE 0x04  // 设备内存，无聚集，无重排序
#define MAIR_ATTR_NORMAL_NC 0x44     // 正常内存，非缓存
#define MAIR_ATTR_NORMAL_WT 0xBB     // 正常内存，直写
#define MAIR_ATTR_NORMAL_WB 0xFF     // 正常内存，回写

// 设置MAIR寄存器
void setup_mair(void) {
    uint64_t mair_val = (MAIR_ATTR_NORMAL_WB << 0) | // 索引0: 回写正常内存
                        (MAIR_ATTR_NORMAL_NC << 8) | // 索引1: 非缓存正常内存
                        (MAIR_ATTR_DEVICE_nGnRnE << 16); // 索引2: 设备内存
    __asm__ volatile("msr mair_el1, %0" : : "r"(mair_val));
}

uint64_t *get_current_page_dir(bool user) {
    uint64_t page_table_base = 0;
    if (user) {
        uint64_t ttbr0_el1 = 0;
        asm volatile("mrs %0, TTBR0_EL1" : "=r"(ttbr0_el1));
        page_table_base = ttbr0_el1 & 0xFFFFFFFFFFF0;
    } else {
        uint64_t ttbr0_el1 = 0;
        asm volatile("mrs %0, TTBR1_EL1" : "=r"(ttbr0_el1));
        page_table_base = ttbr0_el1 & 0xFFFFFFFFFFF0;
    }
    return (uint64_t *)phys_to_virt(page_table_base);
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t attr = ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_4K_PAGE |
                    ARCH_PT_FLAG_INNER_SH | ARCH_PT_FLAG_ACCESS;

    if ((flags & PT_FLAG_W) == 0)
        attr |= ARCH_PT_FLAG_READONLY;
    if ((flags & PT_FLAG_X) == 0)
        attr |= ARCH_PT_FLAG_XN;
    if (flags & PT_FLAG_U)
        attr |= ARCH_PT_FLAG_USER;

    if (flags & PT_FLAG_DEVICE)
        attr |= (0x02 << 2);
    else
        attr |= (0x00 << 2);

    return attr;
}

// 内存屏障和TLB操作
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define tlbi(va) asm volatile("tlbi vae1, %0" : : "r"(va) : "memory")

void arch_flush_tlb(uint64_t vaddr) {
    uint64_t va = vaddr >> 12;

    dsb(ishst); // 确保页表写入完成
    tlbi(va);   // 无效化单个VA的TLB条目
    dsb(ish);   // 等待TLB操作完成
    isb();      // 流水线同步
}
