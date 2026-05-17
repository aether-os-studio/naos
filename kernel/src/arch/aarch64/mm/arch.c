#include "arch.h"
#include <mm/mm.h>
#include <libs/klibc.h>

uint64_t arch_page_table_levels() { return ARCH_MAX_PT_LEVEL; }

uint64_t arch_user_va_limit(void) { return 0x0000ffffffffffffULL; }

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
        uint64_t ttbr1_el1 = 0;
        asm volatile("mrs %0, TTBR1_EL1" : "=r"(ttbr1_el1));
        page_table_base = ttbr1_el1 & 0xFFFFFFFFFFF0;
    }
    return phys_to_virt(page_table_base);
}

void set_current_page_dir(bool user, uint64_t pgdir) {
    if (user) {
        asm volatile("msr TTBR0_EL1, %0" : : "r"(pgdir) : "memory");
    } else {
        asm volatile("msr TTBR1_EL1, %0" : : "r"(pgdir) : "memory");
    }
    arch_flush_tlb_all();
}

void arch_page_table_init(void) { setup_mair(); }

uint64_t arch_page_table_root_entries(int level) {
    (void)level;
    return (1UL << ARCH_PT_OFFSET_PER_LEVEL);
}

uint64_t arch_make_page_table_entry(uint64_t paddr, uint64_t flags) {
    return ARCH_MAKE_PDE(paddr,
                         ARCH_PT_TABLE_FLAGS | (flags & ARCH_PT_FLAG_USER));
}

void arch_page_table_prepare_new(uint64_t *root) { memset(root, 0, PAGE_SIZE); }

void arch_page_table_copy_kernel(uint64_t *dst, uint64_t *src) {
    (void)dst;
    (void)src;
}

bool arch_page_table_flags_writable(uint64_t flags) {
    return (flags & ARCH_PT_FLAG_READONLY) == 0;
}

uint64_t arch_page_table_flags_make_cow(uint64_t flags) {
    return (flags | ARCH_PT_FLAG_COW | ARCH_PT_FLAG_READONLY);
}

uint64_t arch_page_table_flags_make_writable(uint64_t flags) {
    return (flags & ~(ARCH_PT_FLAG_COW | ARCH_PT_FLAG_READONLY));
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

    if (flags & PT_FLAG_UNCACHEABLE)
        attr |= (0x01 << 2);
    if (flags & PT_FLAG_DEVICE)
        attr |= (0x02 << 2);

    if (flags & PT_FLAG_COW)
        attr |= ARCH_PT_FLAG_COW;

    return attr;
}

// 内存屏障和TLB操作
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define tlbi(va) asm volatile("tlbi vale1is, %0" : : "r"((va)) : "memory")

void arch_flush_tlb(uint64_t vaddr) {
    dsb(ishst);
    tlbi(vaddr >> 12); // 无效化单个VA的TLB条目
    dsb(ish);          // 等待TLB操作完成
    isb();             // 流水线同步
}

void arch_flush_tlb_all() {
    asm volatile("dsb ishst\n\t"
                 "tlbi vmalle1is\n\t"
                 "dsb ish\n\t"
                 "isb\n\t");
}
