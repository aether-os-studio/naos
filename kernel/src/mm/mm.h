#pragma once

#include <libs/klibc.h>
#include <mm/bitmap.h>
#include <mm/hhdm.h>
#include <mm/page_table.h>
#include <arch/arch.h>

#define MAX_USABLE_REGIONS_COUNT 128

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

typedef struct
{
    Bitmap bitmap;
    size_t origin_frames;
    size_t usable_frames;
} FrameAllocator;

extern FrameAllocator frame_allocator;

typedef struct task_mm_info
{
    uint64_t page_table_addr;
    uint8_t ref_count;
} task_mm_info_t;

void frame_init();

void free_frames(uint64_t addr, uint64_t size);
uint64_t alloc_frames(size_t count);

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags);
void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size);

void heap_init();

void *malloc(size_t size);
void *calloc(size_t num, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

static inline void *alloc_frames_bytes(uint64_t bytes)
{
    return phys_to_virt((void *)alloc_frames((bytes + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
}

static inline void free_frames_bytes(void *ptr, uint64_t bytes)
{
    free_frames(virt_to_phys((uint64_t)ptr), (bytes + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
}
