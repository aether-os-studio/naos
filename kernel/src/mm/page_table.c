#include <arch/arch.h>
#include <mm/mm.h>
#include <task/task.h>

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

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr, uint64_t flags, bool force)
{
    if (!kernel_page_dir)
        kernel_page_dir = pgdir;

    uint64_t indexs[ARCH_MAX_PT_LEVEL] = {0};
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++)
    {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++)
    {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (!ARCH_PT_IS_TABLE(addr) || !(addr & ARCH_ADDR_MASK))
        {
            uint64_t a = alloc_frames(1);
            if (a == (uint64_t)-1)
            {
                return a;
            }
            memset((uint64_t *)phys_to_virt(a), 0, DEFAULT_PAGE_SIZE);
            pgdir[index] = a | ARCH_PT_TABLE_FLAGS | (flags & ARCH_PT_FLAG_USER);
        }
        if (ARCH_PT_IS_LARGE(addr))
        {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(pgdir[index] & ARCH_ADDR_MASK);
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    if ((pgdir[index] & ARCH_ADDR_MASK) != 0)
    {
        if (force)
        {
            uint64_t paddr = pgdir[index] & ARCH_ADDR_MASK;
            free_frames(paddr, 1);
        }
        else
            return 0;
    }

    pgdir[index] = (paddr & ARCH_ADDR_MASK) | flags;

    arch_flush_tlb(vaddr);

    return 0;
}

uint64_t unmap_page(uint64_t *pgdir, uint64_t vaddr)
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

        if (!ARCH_PT_IS_TABLE(addr))
        {
            return -1;
        }
        if (ARCH_PT_IS_LARGE(addr))
        {
            return -1;
        }
        pgdir = (uint64_t *)phys_to_virt(addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)) & ~get_physical_memory_offset());
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    uint64_t pte = pgdir[index];

    if (pte & ARCH_PT_FLAG_VALID)
    {
        uint64_t paddr = pte & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)) & ~get_physical_memory_offset();
        size_t frame_count = 1;

        free_frames(paddr, frame_count);
        pgdir[index] = 0;
        arch_flush_tlb(vaddr);
    }

    return 0;
}

static page_table_t *copy_page_table_recursive(page_table_t *source_table, int level, bool all_copy, bool kernel_space)
{
    if (source_table == NULL)
        return NULL;
    if (level == 0)
    {
        if (kernel_space)
        {
            return source_table;
        }

        uint64_t frame = alloc_frames(1);
        page_table_t *new_page_table = (page_table_t *)phys_to_virt(frame);
        memcpy(new_page_table, phys_to_virt(source_table)->entries, DEFAULT_PAGE_SIZE);
        return new_page_table;
    }

    uint64_t phy_frame = alloc_frames(1);
    page_table_t *new_table = (page_table_t *)phys_to_virt(phy_frame);
    for (uint64_t i = 0; i <
#if defined(__x86_64__)
                         (all_copy ? 512 : (level == ARCH_MAX_PT_LEVEL ? 256 : 512));
#else
                         512;
#endif
         i++)
    {
        if (ARCH_PT_IS_LARGE(phys_to_virt(source_table)->entries[i].value))
        {
            new_table->entries[i].value = phys_to_virt(source_table)->entries[i].value;
            continue;
        }

        page_table_t *source_page_table_next = (page_table_t *)(phys_to_virt(source_table)->entries[i].value & ARCH_ADDR_MASK);
        page_table_t *new_page_table = copy_page_table_recursive(source_page_table_next, level - 1, all_copy, level != ARCH_MAX_PT_LEVEL ? kernel_space : i >= 256);
        new_table->entries[i].value = (uint64_t)virt_to_phys((uint64_t)new_page_table) | (phys_to_virt(source_table)->entries[i].value & ~ARCH_ADDR_MASK);
    }
    return new_table;
}

static void free_page_table_recursive(page_table_t *table, int level)
{
    if (table == phys_to_virt(NULL))
        return;
    if (level == 0)
    {
        free_frames((uint64_t)virt_to_phys((uint64_t)table), 1);
        return;
    }

    for (int i = 0; i <

#if defined(__x86_64__)
                    (level == ARCH_MAX_PT_LEVEL ? 256 : 512);
#else
                    512;
#endif
         i++)
    {
        page_table_t *page_table_next = (page_table_t *)phys_to_virt(table->entries[i].value & ARCH_ADDR_MASK);
        free_page_table_recursive(page_table_next, level - 1);
    }
    free_frames((uint64_t)virt_to_phys((uint64_t)table), 1);
}

spinlock_t clone_lock = {0};

task_mm_info_t *clone_page_table(task_mm_info_t *old, uint64_t clone_flags)
{
    if (old && (clone_flags & CLONE_VM))
    {
        old->ref_count++;
        return old;
    }
    spin_lock(&clone_lock);
    task_mm_info_t *new_mm = (task_mm_info_t *)malloc(sizeof(task_mm_info_t));
    memset(new_mm, 0, sizeof(task_mm_info_t));
    new_mm->page_table_addr = virt_to_phys((uint64_t)copy_page_table_recursive((page_table_t *)old->page_table_addr, ARCH_MAX_PT_LEVEL, !!(clone_flags & CLONE_VM), false));
#if defined(__x86_64__)
    memcpy((uint64_t *)phys_to_virt(new_mm->page_table_addr) + 256, (uint64_t *)phys_to_virt(old->page_table_addr) + 256, DEFAULT_PAGE_SIZE / 2);
#endif
    new_mm->ref_count = 1;
    spin_unlock(&clone_lock);
    return new_mm;
}

void free_page_table(task_mm_info_t *directory)
{
    spin_lock(&clone_lock);

    if (directory->ref_count <= 1)
    {
        free_page_table_recursive((page_table_t *)phys_to_virt(directory->page_table_addr), ARCH_MAX_PT_LEVEL);
        free(directory);
    }
    else
    {
        directory->ref_count--;
    }

    spin_unlock(&clone_lock);
}

void page_table_init()
{
    uint64_t new_page_table = alloc_frames(1);
    memset((void *)phys_to_virt(new_page_table), 0, DEFAULT_PAGE_SIZE);
#if defined(__x86_64__)
    memcpy((uint64_t *)phys_to_virt(new_page_table) + 256, (uint64_t *)get_current_page_dir(false) + 256, DEFAULT_PAGE_SIZE / 2);
    asm volatile("movq %0, %%cr3" ::"r"(new_page_table));
#endif
    kernel_page_dir = (uint64_t *)phys_to_virt(new_page_table);
}
