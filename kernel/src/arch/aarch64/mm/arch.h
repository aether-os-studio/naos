#pragma once

#define ARCH_MAX_PT_LEVEL 4

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

#define ARCH_PT_FLAG_VALID ((uint64_t)1 << 0)
#define ARCH_PT_FLAG_TABLE ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_4K_PAGE ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_BLOCK ((uint64_t)0 << 1)
#define ARCH_PT_FLAG_USER ((uint64_t)1 << 6)
#define ARCH_PT_FLAG_READONLY ((uint64_t)1 << 7)
#define ARCH_PT_FLAG_INNER_SH ((uint64_t)3 << 8)
#define ARCH_PT_FLAG_ACCESS ((uint64_t)1 << 10)
#define ARCH_PT_FLAG_XN ((uint64_t)1 << 54)
#define ARCH_PT_FLAG_WB ((uint64_t)0 << 2)
#define ARCH_PT_FLAG_FB ((uint64_t)1 << 2)
#define ARCH_ADDR_MASK ((uint64_t)0x0000FFFFFFFFF000)

#define ARCH_READ_PTE(pte) ((uint64_t)(pte) & ARCH_ADDR_MASK)
#define ARCH_MAKE_PTE(paddr, flags)                                            \
    (((uint64_t)(paddr) & ARCH_ADDR_MASK) | (flags))
#define ARCH_READ_PTE_FLAG(pte) ((uint64_t)(pte) & ~ARCH_ADDR_MASK)

#define ARCH_PT_TABLE_FLAGS                                                    \
    (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE | ARCH_PT_FLAG_ACCESS)

#define ARCH_PT_IS_TABLE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE)) ==                      \
     (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE))
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE)) == ARCH_PT_FLAG_VALID)

uint64_t get_arch_page_table_flags(uint64_t flags);
void arch_flush_tlb(uint64_t vaddr);
