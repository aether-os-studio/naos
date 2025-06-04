#include <arch/arch.h>
#include <mm/mm.h>

uint64_t translate_address(uint64_t *pgdir, uint64_t vaddr)
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
            return (pgdir[index] & (~PAGE_CALC_PAGE_TABLE_MASK(i + 1))) + (vaddr & PAGE_CALC_PAGE_TABLE_MASK(i + 1));
        }
        if (!ARCH_PT_IS_TABLE(addr))
        {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    return (pgdir[index] & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL))) + (vaddr & PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL));
}

uint64_t *kernel_page_dir = NULL;

uint64_t *get_kernel_page_dir()
{
    return kernel_page_dir;
}

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr, uint64_t flags)
{
    if (!kernel_page_dir)
        kernel_page_dir = pgdir;

    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++)
    {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++)
    {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (!ARCH_PT_IS_TABLE(addr))
        {
            uint64_t a = alloc_frames(1);
            memset((uint64_t *)phys_to_virt(a), 0, DEFAULT_PAGE_SIZE);
            pgdir[index] = a | ARCH_PT_TABLE_FLAGS | (flags & ARCH_PT_FLAG_USER);
        }
        if (ARCH_PT_IS_LARGE(addr))
        {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(pgdir[index] & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    if (pgdir[index] == 0)
        pgdir[index] = (paddr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL))) | flags;

    arch_flush_tlb(vaddr);

    return 0;
}

uint64_t unmap_page(uint64_t *pgdir, uint64_t vaddr)
{
    return 0;
}
