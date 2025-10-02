#pragma once

#define ARCH_MAX_PT_LEVEL 4

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

#define ARCH_PT_FLAG_VALID (0x1UL << 0)
#define ARCH_PT_FLAG_READ (0x1UL << 1)
#define ARCH_PT_FLAG_WRITE (0x1UL << 2)
#define ARCH_PT_FLAG_EXEC (0x1UL << 3)
#define ARCH_PT_FLAG_USER (0x1UL << 4)
#define ARCH_PT_FLAG_ACCESSED (0x1UL << 6)
#define ARCH_PT_FLAG_DIRTY (0x1UL << 7)
#define ARCH_PT_FLAG_PBMT_NC (0x1UL << 62)
#define ARCH_ADDR_MASK ((uint64_t)0x003ffffffffffc00)

#define ARCH_PT_TABLE_FLAGS ARCH_PT_FLAG_VALID

#define ARCH_PT_FLAG_RWX                                                       \
    (ARCH_PT_FLAG_READ | ARCH_PT_FLAG_WRITE | ARCH_PT_FLAG_EXEC)

#define ARCH_PT_IS_TABLE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_RWX)) == ARCH_PT_FLAG_VALID)
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_RWX)) > ARCH_PT_FLAG_VALID)

uint64_t get_arch_page_table_flags(uint64_t flags);
void arch_flush_tlb(uint64_t vaddr);
