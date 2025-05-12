#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

#define ARCH_PT_FLAG_VALID ((uint64_t)1 << 0)
#define ARCH_PT_FLAG_TABLE ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_4K_PAGE ((uint64_t)1 << 1)
#define ARCH_PT_FLAG_BLOCK ((uint64_t)0 << 1)
#define ARCH_PT_FLAG_USER ((uint64_t)1 << 6)
#define ARCH_PT_FLAG_READONLY ((uint64_t)1 << 7)
#define ARCH_PT_FLAG_INNER_SH ((uint64_t)3 << 8)
#define ARCH_PT_FLAG_ACCESS ((uint64_t)1 << 10)
#define ARCH_PT_FLAG_XN ((uint64_t)3 << 53)
#define ARCH_PT_FLAG_WB ((uint64_t)0 << 2)
#define ARCH_PT_FLAG_FB ((uint64_t)1 << 2)
#define ARCH_ADDR_MASK ((uint64_t)0x0000FFFFFFFFF000)

#define ARCH_PT_TABLE_FLAGS (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE | ARCH_PT_FLAG_ACCESS)

#define PT_IS_TABLE(x) (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE)) == (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_TABLE))

uint64_t get_arch_page_table_flags(uint64_t flags);

uint64_t *get_kernel_page_dir();
uint64_t *get_current_page_dir(bool user);
void map_page(uint64_t *pml4, uint64_t va, uint64_t pa, uint64_t flags);
void unmap_page(uint64_t *pml4, uint64_t va);

uint64_t clone_page_table(uint64_t cr3_old, uint64_t range_start, uint64_t range_end);
void free_page_table(uint64_t directory);
uint64_t translate_address(uint64_t *pml4, uint64_t vaddr);
