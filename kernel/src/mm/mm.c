#include <arch/arch.h>
#include <mm/mm.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST,
    .revision = 0,
};

FrameAllocator frame_allocator;
uint64_t memory_size = 0;

void frame_init()
{
    hhdm_init();

    struct limine_memmap_response *memory_map = memmap_request.response;

    for (uint64_t i = memory_map->entry_count - 1; i != 0; i--)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            memory_size = region->base + region->length;
            break;
        }
    }

    uint64_t last_size = UINT64_MAX;

    size_t bitmap_size = (memory_size / DEFAULT_PAGE_SIZE + 7) / 8;
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

    Bitmap *bitmap = &frame_allocator.bitmap;
    bitmap_init(bitmap, (uint8_t *)phys_to_virt(bitmap_address), bitmap_size);

    size_t origin_frames = 0;
    for (uint64_t i = 0; i < memory_map->entry_count; i++)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            size_t start_frame = region->base / DEFAULT_PAGE_SIZE;
            size_t frame_count = region->length / DEFAULT_PAGE_SIZE;
            origin_frames += frame_count;
            bitmap_set_range(bitmap, start_frame, start_frame + frame_count, true);
        }
    }

    size_t bitmap_frame_start = bitmap_address / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_count = (bitmap_size + 4095) / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_end = bitmap_frame_start + bitmap_frame_count;
    bitmap_set_range(bitmap, bitmap_frame_start, bitmap_frame_end, false);

    frame_allocator.origin_frames = origin_frames;
    frame_allocator.usable_frames = origin_frames - bitmap_frame_count;
}

void free_frames(uint64_t addr, uint64_t size)
{
    if (addr == 0)
        return;
    size_t frame_index = addr / DEFAULT_PAGE_SIZE;
    size_t frame_count = size;
    if (frame_index == 0)
        return;
    Bitmap *bitmap = &frame_allocator.bitmap;
    bitmap_set_range(bitmap, frame_index, frame_index + frame_count, true);
    frame_allocator.usable_frames += frame_count;
}

uint64_t alloc_frames(size_t count)
{
    Bitmap *bitmap = &frame_allocator.bitmap;
    size_t frame_index = bitmap_find_range(bitmap, count, true);

    if (frame_index == (size_t)-1)
        return 0;
    bitmap_set_range(bitmap, frame_index, frame_index + count, false);
    frame_allocator.usable_frames -= count;

    return frame_index * DEFAULT_PAGE_SIZE;
}

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags)
{
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        if (paddr == 0)
            map_page(pml4, va, alloc_frames(1), get_arch_page_table_flags(flags));
        else
            map_page(pml4, va, paddr + (va - vaddr), get_arch_page_table_flags(flags));
    }
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size)
{
    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        unmap_page(pml4, va);
    }
}
