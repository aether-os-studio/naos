#pragma once

#include <libs/klibc.h>
#include <mm/page_table_flags.h>

#define PAGE_CALC_PAGE_TABLE_SIZE(level)                                       \
    ((uint64_t)1 << (ARCH_PT_OFFSET_BASE + (ARCH_MAX_PT_LEVEL - (level)) *     \
                                               ARCH_PT_OFFSET_PER_LEVEL))
#define PAGE_CALC_PAGE_TABLE_MASK(level)                                       \
    (PAGE_CALC_PAGE_TABLE_SIZE(level) - (uint64_t)1)
#define PAGE_CALC_PAGE_TABLE_INDEX(vaddr, level)                               \
    (((vaddr) >> (ARCH_PT_OFFSET_BASE +                                        \
                  (ARCH_MAX_PT_LEVEL - (level)) * ARCH_PT_OFFSET_PER_LEVEL)) & \
     (((uint64_t)1 << ARCH_PT_OFFSET_PER_LEVEL) - 1))

uint64_t *get_kernel_page_dir();
uint64_t *get_current_page_dir(bool user);

struct task_mm_info;
typedef struct task_mm_info task_mm_info_t;

task_mm_info_t *clone_page_table(task_mm_info_t *old, uint64_t clone_flags);
void free_page_table(task_mm_info_t *directory);

uint64_t translate_address(uint64_t *pgdir, uint64_t vaddr);

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr,
                  uint64_t flags, bool force);
uint64_t unmap_page(uint64_t *pgdir, uint64_t vaddr);

void page_table_init();
