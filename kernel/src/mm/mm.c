#include <arch/arch.h>
#include <mm/mm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST,
    .revision = 0,
};

spinlock_t frame_op_lock = {0};

FrameAllocator frame_allocator;
uint64_t memory_size = 0;

uint64_t get_memory_size()
{
    uint64_t all_memory_size = 0;
    struct limine_memmap_response *memory_map = memmap_request.response;

    for (uint64_t i = memory_map->entry_count - 1; i > 0; i--)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            all_memory_size = region->base + region->length;
            break;
        }
    }

    return all_memory_size;
}

void frame_init()
{
    hhdm_init();

    struct limine_memmap_response *memory_map = memmap_request.response;

    memory_size = get_memory_size();

    size_t bitmap_size = (memory_size / DEFAULT_PAGE_SIZE + 63) / 64;
    uint64_t bitmap_address = 0;

    for (uint64_t i = 0; i < memory_map->entry_count; i++)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];
        if (region->type == LIMINE_MEMMAP_USABLE)
        {
            if (region->length >= bitmap_size)
            {
                bitmap_address = region->base;
                break;
            }
        }
    }

    Bitmap *bitmap = &frame_allocator.bitmap;
    bitmap_init(bitmap, (uint64_t *)phys_to_virt(bitmap_address), bitmap_size);

    size_t origin_frames = 0;
    for (uint64_t i = 0; i < memory_map->entry_count; i++)
    {
        struct limine_memmap_entry *region = memory_map->entries[i];

        size_t start_frame = region->base / DEFAULT_PAGE_SIZE;
        size_t frame_count = region->length / DEFAULT_PAGE_SIZE;
        origin_frames += frame_count;
        bitmap_set_range(bitmap, start_frame, start_frame + frame_count, (region->type == LIMINE_MEMMAP_USABLE));
    }

    size_t low_1M_frame_count = 0x100000 / DEFAULT_PAGE_SIZE;
    bitmap_set_range(bitmap, 0, low_1M_frame_count, false);

    size_t bitmap_frame_start = bitmap_address / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_count = (bitmap_size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE;
    size_t bitmap_frame_end = bitmap_frame_start + bitmap_frame_count;
    bitmap_set_range(bitmap, bitmap_frame_start, bitmap_frame_end, false);

    frame_allocator.origin_frames = origin_frames;
    frame_allocator.usable_frames = origin_frames - bitmap_frame_count - low_1M_frame_count;
}

static uint64_t last_alloc_pos = 0;

uint64_t alloc_frames(size_t count)
{
    spin_lock(&frame_op_lock);

    Bitmap *bitmap = &frame_allocator.bitmap;

    if (frame_allocator.usable_frames < count)
    {
        spin_unlock(&frame_op_lock);
        return 0;
    }

retry:
    size_t frame_index = bitmap_find_range_from(bitmap, count, true, last_alloc_pos);

    if (frame_index != (size_t)-1)
    {
        last_alloc_pos = frame_index + count;
        bitmap_set_range(bitmap, frame_index, frame_index + count, false);
        frame_allocator.usable_frames -= count;
        spin_unlock(&frame_op_lock);
        return frame_index * DEFAULT_PAGE_SIZE;
    }

    if (last_alloc_pos != 0)
    {
        last_alloc_pos = 0;
        goto retry;
    }

    printk("Allocate frame failed!!!\n");

    spin_unlock(&frame_op_lock);

    return 0;
}

void free_frames(uint64_t addr, uint64_t size)
{
    spin_lock(&frame_op_lock);

    if (addr == 0)
    {
        spin_unlock(&frame_op_lock);
        return;
    }

    size_t frame_index = addr / DEFAULT_PAGE_SIZE;

    bitmap_set_range(&frame_allocator.bitmap, frame_index, frame_index + size, true);
    frame_allocator.usable_frames += size;

    spin_unlock(&frame_op_lock);
}

bool mem_map_op_lock = false;

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags)
{
    while (mem_map_op_lock)
    {
        arch_pause();
    }

    mem_map_op_lock = true;

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        if (paddr == 0)
        {
            uint64_t phys = alloc_frames(1);
            if (phys == (uint64_t)-1)
            {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags));
        }
        else
        {
            map_page(pml4, va, paddr + (va - vaddr), get_arch_page_table_flags(flags));
        }
    }

    mem_map_op_lock = false;
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size)
{
    while (mem_map_op_lock)
    {
        arch_pause();
    }

    mem_map_op_lock = true;

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        unmap_page(pml4, va);
    }

    mem_map_op_lock = false;
}

uint64_t map_change_attribute(uint64_t *pgdir, uint64_t vaddr, uint64_t flags)
{
    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++)
    {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++)
    {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr))
        {
            pgdir[index] &= ~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL);
            pgdir[index] |= flags;
        }
        if (!ARCH_PT_IS_TABLE(addr))
        {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];

    pgdir[index] &= ~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL);
    pgdir[index] |= flags;

    arch_flush_tlb(vaddr);

    return 0;
}

uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr, uint64_t len, uint64_t flags)
{
    while (mem_map_op_lock)
    {
        arch_pause();
    }

    mem_map_op_lock = true;

    for (uint64_t va = vaddr; va < vaddr + len; va += DEFAULT_PAGE_SIZE)
    {
        map_change_attribute(pgdir, va, get_arch_page_table_flags(flags));
    }

    mem_map_op_lock = false;

    return 0;
}
