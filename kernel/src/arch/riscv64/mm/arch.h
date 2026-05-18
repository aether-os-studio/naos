#pragma once

#define ARCH_MAX_PT_LEVEL 5

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

#define ARCH_PT_FLAG_VALID ((uint64_t)1 << 0)
#define ARCH_PT_FLAG_PRESENT ARCH_PT_FLAG_VALID
#define ARCH_PT_FLAG_READ ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_WRITE ((uint64_t)1 << 2)
#define ARCH_PT_FLAG_WRITEABLE ARCH_PT_FLAG_WRITE
#define ARCH_PT_FLAG_EXEC ((uint64_t)1 << 3)
#define ARCH_PT_FLAG_USER ((uint64_t)1 << 4)
#define ARCH_PT_FLAG_GLOBAL ((uint64_t)1 << 5)
#define ARCH_PT_FLAG_ACCESS ((uint64_t)1 << 6)
#define ARCH_PT_FLAG_DIRTY ((uint64_t)1 << 7)
#define ARCH_PT_FLAG_COW ((uint64_t)1 << 8)
#define ARCH_PT_SOFT_FLAGS ARCH_PT_FLAG_COW
#define ARCH_PTE_PPN_MASK ((uint64_t)0x003FFFFFFFFFFC00)

#define ARCH_READ_PTE(pte) ((((uint64_t)(pte) & ARCH_PTE_PPN_MASK) >> 10) << 12)
#define ARCH_MAKE_PTE(paddr, flags)                                            \
    (((((uint64_t)(paddr)) >> 12) << 10) | (flags))
#define ARCH_MAKE_PDE(paddr, flags)                                            \
    (((((uint64_t)(paddr)) >> 12) << 10) | ARCH_PT_FLAG_VALID)
#define ARCH_READ_PTE_FLAG(pte) ((uint64_t)(pte) & ~ARCH_PTE_PPN_MASK)

#define ARCH_MAKE_HUGE_PTE(paddr, flags) ARCH_MAKE_PTE((paddr), (flags))

#define ARCH_PT_TABLE_FLAGS (ARCH_PT_FLAG_VALID)

#define ARCH_PT_IS_TABLE(x)                                                    \
    (((x) & ARCH_PT_FLAG_VALID) &&                                             \
     (((x) & (ARCH_PT_FLAG_READ | ARCH_PT_FLAG_WRITE | ARCH_PT_FLAG_EXEC)) ==  \
      0))
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & ARCH_PT_FLAG_VALID) &&                                             \
     (((x) & (ARCH_PT_FLAG_READ | ARCH_PT_FLAG_WRITE | ARCH_PT_FLAG_EXEC)) !=  \
      0))

uint64_t get_arch_page_table_flags(uint64_t flags);
uint64_t arch_page_table_levels();
uint64_t riscv64_make_satp(uint64_t root_paddr);
void riscv64_set_page_table_root(uint64_t root_paddr);
void arch_flush_tlb(uint64_t vaddr);
void arch_flush_tlb_all();
