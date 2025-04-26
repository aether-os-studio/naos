#pragma once

#include <libs/klibc.h>
#include <mm/bitmap.h>
#include <mm/hhdm.h>
#include <mm/heap.h>
#include <mm/page_table_flags.h>
#include <arch/arch.h>

#define MAX_USABLE_REGIONS_COUNT 128

#define NA_DEFAULT_PAGE_SIZE 4096

typedef struct
{
    NA_Bitmap bitmap;
    size_t origin_frames;
    size_t usable_frames;
} FrameAllocator;

extern FrameAllocator frame_allocator;

void NA_frame_init();

void NA_free_frames(uint64_t addr, uint64_t size);
uint64_t NA_alloc_frames(size_t count);

void NA_map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags);
void NA_unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size);
