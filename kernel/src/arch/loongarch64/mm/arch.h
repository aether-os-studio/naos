#pragma once

#define ARCH_MAX_PT_LEVEL 4

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

#define ARCH_PT_FLAG_VALID (0x1UL << 0)
#define ARCH_PT_FLAG_DIRTY (0x1UL << 1)
#define ARCH_PT_FLAG_USER ((0x1UL << 2) | (0x1UL << 3))
#define ARCH_PT_FLAG_MAT_CC (0x1UL << 4)
#define ARCH_PT_FLAG_MAT_WUC (0x1UL << 5)
#define ARCH_PT_FLAG_GLOBAL (0x1UL << 6)
#define ARCH_PT_FLAG_HUGE (0x1UL << 6)
#define ARCH_PT_FLAG_COW (0x1UL << 7)
#define ARCH_PT_FLAG_WRITEABLE (0x1UL << 8)
#define ARCH_PT_FLAG_ALLOC (0x1UL << 9)
#define ARCH_PT_FLAG_HGLOBAL (0x1UL << 12)
#define ARCH_PT_FLAG_NR (0x1UL << 61)
#define ARCH_PT_FLAG_NX (0x1UL << 62)
#define ARCH_ADDR_MASK ((uint64_t)0x0000FFFFFFFFF000)

#define ARCH_PT_TABLE_FLAGS 0

#define ARCH_READ_PTE(pte) ((uint64_t)(pte) & ARCH_ADDR_MASK)
#define ARCH_MAKE_PTE(paddr, flags)                                            \
    (((uint64_t)(paddr) & ARCH_ADDR_MASK) | (flags))
#define ARCH_READ_PTE_FLAG(pte) ((uint64_t)(pte) & ~ARCH_ADDR_MASK)

#define ARCH_MAKE_HUGE_PTE(paddr, flags)                                       \
    (((uint64_t)(paddr) & ARCH_ADDR_MASK) | ARCH_PT_FLAG_VALID |               \
     ARCH_PT_FLAG_HGLOBAL | ARCH_PT_FLAG_HUGE | (flags))

#define ARCH_PT_IS_TABLE(x) ((!((x) & (ARCH_PT_FLAG_VALID))) && ((x) != 0))
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_HGLOBAL | ARCH_PT_FLAG_HUGE)) ==                     \
     (ARCH_PT_FLAG_HGLOBAL | ARCH_PT_FLAG_HUGE))

uint64_t get_arch_page_table_flags(uint64_t flags);
void arch_flush_tlb(uint64_t vaddr);
