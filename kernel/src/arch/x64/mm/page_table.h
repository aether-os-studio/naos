#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

#define NA_ARCH_PT_FLAG_VALID (0x1UL << 0)
#define NA_ARCH_PT_FLAG_WRITEABLE (0x1UL << 1)
#define NA_ARCH_PT_FLAG_USER (0x1UL << 2)
#define NA_ARCH_PT_FLAG_HUGE (0x1UL << 7)
#define NA_ARCH_PT_FLAG_NX (0x1UL << 63)

#define NA_ARCH_ADDR_MASK 0x000FFFFFFFFFF000

uint64_t NA_get_arch_page_table_flags(uint64_t flags);
void NA_map_page(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t arch_flags);
void NA_unmap_page(uint64_t *pml4, uint64_t vaddr);
uint64_t *get_current_page_dir();
