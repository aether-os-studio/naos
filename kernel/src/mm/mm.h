#pragma once

#include <libs/klibc.h>
#include <mm/hhdm.h>
#include <mm/buddy.h>
#include <mm/page_table.h>
#include <arch/arch.h>
#include <mm/vma.h>

#define MAX_USABLE_REGIONS_COUNT 128

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

typedef struct task_mm_info {
    uint64_t page_table_addr;
    int ref_count;
    vma_manager_t task_vma_mgr;
    uint64_t brk_start;
    uint64_t brk_current;
    uint64_t brk_end;
} task_mm_info_t;

void frame_init();

uintptr_t alloc_frames(size_t count);
void free_frames(uintptr_t addr, size_t count);

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                    uint64_t size, uint64_t flags);
void map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                            uint64_t size, uint64_t flags);
void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size);
uint64_t map_change_attribute(uint64_t *pml4, uint64_t vaddr, uint64_t flags);
uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags);

void heap_init();

void *malloc(size_t size);
void *aligned_alloc(size_t align, size_t size);
void *calloc(size_t num, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

typedef struct {
    uintptr_t addr;
    size_t actual_count; // 实际分配的页数
} alloc_result_t;

static inline void *alloc_frames_bytes(uint64_t bytes) {
    uint64_t addr = phys_to_virt(
        alloc_frames((bytes + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
    return (void *)addr;
}

static inline void free_frames_bytes(void *ptr, uint64_t bytes) {
    free_frames(virt_to_phys((uint64_t)ptr),
                (bytes + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
}
