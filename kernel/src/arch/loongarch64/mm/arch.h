#pragma once

#define ARCH_MAX_PT_LEVEL 4

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

/* LoongArch64 leaf PTE layout. Upper-level directory entries are raw,
 * page-aligned child-table physical addresses. */
#define ARCH_PT_FLAG_HW_VALID ((uint64_t)1 << 0)
#define ARCH_PT_FLAG_ACCESS ARCH_PT_FLAG_HW_VALID
#define ARCH_PT_FLAG_DIRTY ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_PLV_MASK ((uint64_t)3 << 2)
#define ARCH_PT_FLAG_USER ((uint64_t)3 << 2)
#define ARCH_PT_FLAG_CACHE_CC ((uint64_t)1 << 4)
#define ARCH_PT_FLAG_GLOBAL ((uint64_t)1 << 6)
#define ARCH_PT_FLAG_HUGE ((uint64_t)1 << 6)
#define ARCH_PT_FLAG_PRESENT ((uint64_t)1 << 7)
#define ARCH_PT_FLAG_VALID ARCH_PT_FLAG_PRESENT
#define ARCH_PT_FLAG_WRITE ((uint64_t)1 << 8)
#define ARCH_PT_FLAG_WRITEABLE ARCH_PT_FLAG_WRITE
#define ARCH_PT_FLAG_MODIFIED ((uint64_t)1 << 9)
#define ARCH_PT_FLAG_NO_READ ((uint64_t)1 << 61)
#define ARCH_PT_FLAG_NO_EXEC ((uint64_t)1 << 62)
#define ARCH_PT_FLAG_COW ((uint64_t)1 << 10)
#define ARCH_PT_SOFT_FLAGS ARCH_PT_FLAG_COW
#define ARCH_PTE_ADDR_MASK ((uint64_t)0x0000FFFFFFFFF000)

#define ARCH_READ_PTE(pte) ((uint64_t)(pte) & ARCH_PTE_ADDR_MASK)
#define ARCH_MAKE_PTE(paddr, flags)                                            \
    (((uint64_t)(paddr) & ARCH_PTE_ADDR_MASK) | (flags))
#define ARCH_MAKE_PDE(paddr, flags)                                            \
    ((void)(flags), ((uint64_t)(paddr) & ARCH_PTE_ADDR_MASK))
#define ARCH_READ_PTE_FLAG(pte) ((uint64_t)(pte) & ~ARCH_PTE_ADDR_MASK)

#define ARCH_MAKE_HUGE_PTE(paddr, flags)                                       \
    ARCH_MAKE_PTE((paddr), (flags) | ARCH_PT_FLAG_HUGE)

#define ARCH_PT_TABLE_FLAGS 0

#define ARCH_PT_IS_TABLE(x)                                                    \
    (((x) & ARCH_PTE_ADDR_MASK) != 0 && (((x) & ARCH_PT_FLAG_PRESENT) == 0))
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_PRESENT | ARCH_PT_FLAG_HUGE)) ==                     \
     (ARCH_PT_FLAG_PRESENT | ARCH_PT_FLAG_HUGE))

uint64_t get_arch_page_table_flags(uint64_t flags);
uint64_t arch_page_table_levels();
uint64_t *get_current_page_dir(bool user);
void loongarch64_set_user_page_table_root(uint64_t root_paddr);
void arch_flush_tlb(uint64_t vaddr);
void arch_flush_tlb_all();
