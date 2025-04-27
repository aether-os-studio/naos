#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

#define ARCH_PT_FLAG_VALID (0x1UL << 0)
#define ARCH_PT_FLAG_WRITEABLE (0x1UL << 1)
#define ARCH_PT_FLAG_USER (0x1UL << 2)
#define ARCH_PT_FLAG_HUGE (0x1UL << 7)
#define ARCH_PT_FLAG_NX (0x1UL << 63)

#define ARCH_ADDR_MASK 0x000FFFFFFFFFF000

uint64_t get_arch_page_table_flags(uint64_t flags);
void map_page(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t arch_flags);
void unmap_page(uint64_t *pml4, uint64_t vaddr);
uint64_t *get_kernel_page_dir();
uint64_t *get_current_page_dir();
uint64_t clone_page_table(uint64_t cr3_old, uint64_t user_stack_start, uint64_t user_stack_end);
