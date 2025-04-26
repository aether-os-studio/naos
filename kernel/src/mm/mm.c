#include <mm/mm.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST,
    .revision = 0,
};

FrameAllocator frame_allocator;
uint64_t memory_size = 0;

void NA_frame_init()
{
    NA_hhdm_init();

    struct limine_memmap_response *memory_map = memmap_request.response;

    for (uint64_t i = memory_map->entry_count - 1; i >= 0; i--)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            memory_size = region->base + region->length;
            break;
        }
    }

    uint64_t last_size = UINT64_MAX;

    size_t bitmap_size = (memory_size / NA_DEFAULT_PAGE_SIZE + 7) / 8;
    uint64_t bitmap_address = 0;

    for (uint64_t i = 0; i < memory_map->entry_count; i++)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE && region->length >= bitmap_size && region->length < last_size)
        {
            last_size = region->length;
            bitmap_address = region->base;
        }
    }

    if (!bitmap_address)
        return;

    NA_Bitmap *bitmap = &frame_allocator.bitmap;
    NA_bitmap_init(bitmap, (uint8_t *)NA_phys_to_virt(bitmap_address), bitmap_size);

    size_t origin_frames = 0;
    for (uint64_t i = 0; i < memory_map->entry_count; i++)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            size_t start_frame = region->base / NA_DEFAULT_PAGE_SIZE;
            size_t frame_count = region->length / NA_DEFAULT_PAGE_SIZE;
            origin_frames += frame_count;
            NA_bitmap_set_range(bitmap, start_frame, start_frame + frame_count, true);
        }
    }

    size_t bitmap_frame_start = bitmap_address / NA_DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_count = (bitmap_size + 4095) / NA_DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_end = bitmap_frame_start + bitmap_frame_count;
    NA_bitmap_set_range(bitmap, bitmap_frame_start, bitmap_frame_end, false);

    frame_allocator.origin_frames = origin_frames;
    frame_allocator.usable_frames = origin_frames - bitmap_frame_count;
}

void NA_free_frames(uint64_t addr, uint64_t size)
{
    if (addr == 0)
        return;
    size_t frame_index = addr / NA_DEFAULT_PAGE_SIZE;
    size_t frame_count = size;
    if (frame_index == 0)
        return;
    NA_Bitmap *bitmap = &frame_allocator.bitmap;
    NA_bitmap_set_range(bitmap, frame_index, frame_index + frame_count, true);
    frame_allocator.usable_frames += frame_count;
}

uint64_t NA_alloc_frames(size_t count)
{
    NA_Bitmap *bitmap = &frame_allocator.bitmap;
    size_t frame_index = NA_bitmap_find_range(bitmap, count, true);

    if (frame_index == (size_t)-1)
        return 0;
    NA_bitmap_set_range(bitmap, frame_index, frame_index + count, false);
    frame_allocator.usable_frames -= count;

    return frame_index * NA_DEFAULT_PAGE_SIZE;
}

void NA_map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags)
{
    for (uint64_t va = vaddr; va < vaddr + size; va += NA_DEFAULT_PAGE_SIZE)
    {
        if (paddr == 0)
            NA_map_page(pml4, va, NA_alloc_frames(1), NA_get_arch_page_table_flags(flags));
        else
            NA_map_page(pml4, va, paddr + (va - vaddr), NA_get_arch_page_table_flags(flags));
    }
}

void NA_unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size)
{
    for (uint64_t va = vaddr; va < vaddr + size; va += NA_DEFAULT_PAGE_SIZE)
    {
        NA_unmap_page(pml4, va);
    }
}
