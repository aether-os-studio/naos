#include <arch/arch.h>
#include <mm/mm.h>
#include <task/task.h>

#if !defined(__riscv__)
uint64_t translate_address(uint64_t *pgdir, uint64_t vaddr) {
    if (!vaddr)
        return 0;

    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            return (pgdir[index] & (~PAGE_CALC_PAGE_TABLE_MASK(i + 1)) &
                    ~get_physical_memory_offset()) +
                   (vaddr & PAGE_CALC_PAGE_TABLE_MASK(i + 1));
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(
            addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)) &
            ~get_physical_memory_offset());
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    return (pgdir[index] & ARCH_ADDR_MASK) +
           (vaddr & PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL));
}
#endif

uint64_t *kernel_page_dir = NULL;

uint64_t *get_kernel_page_dir() { return kernel_page_dir; }

#if !defined(__riscv__)
uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr,
                  uint64_t flags, bool force) {
    if (!kernel_page_dir)
        kernel_page_dir = pgdir;

    uint64_t indexs[ARCH_MAX_PT_LEVEL] = {0};
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            return 0;
        }
        if (!ARCH_PT_IS_TABLE(addr) || !(addr & ARCH_ADDR_MASK)) {
            uint64_t a = alloc_frames(1);
            if (a == 0) {
                return a;
            }
            memset((uint64_t *)phys_to_virt(a), 0, DEFAULT_PAGE_SIZE);
            pgdir[index] =
                a | ARCH_PT_TABLE_FLAGS | (flags & ARCH_PT_FLAG_USER);
        }
        pgdir = (uint64_t *)phys_to_virt(pgdir[index] & ARCH_ADDR_MASK);
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    if ((pgdir[index] & ARCH_ADDR_MASK) != 0) {
        if (force) {
            uint64_t addr = pgdir[index] & ARCH_ADDR_MASK;
            // if (bitmap_get(&frame_allocator.bitmap, addr / DEFAULT_PAGE_SIZE)
            // !=
            //     true)
            //     free_frames(addr, 1);
        } else
            return 0;
    }

    pgdir[index] = (paddr & ARCH_ADDR_MASK) | flags;

    arch_flush_tlb(vaddr);

    return 0;
}
#endif

uint64_t unmap_page(uint64_t *pgdir, uint64_t vaddr) {
    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    uint64_t *table_ptrs[ARCH_MAX_PT_LEVEL];
    uint64_t table_indices[ARCH_MAX_PT_LEVEL];

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    // 保存每一级页表的指针和索引
    table_ptrs[0] = pgdir;
    table_indices[0] = indexs[0];

    // 遍历页表层级
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = table_indices[i];
        uint64_t addr = table_ptrs[i][index];
        if (ARCH_PT_IS_LARGE(addr)) {
            return 0; // 大页映射，不支持部分释放
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0; // 页表不存在
        }
        table_ptrs[i + 1] = (uint64_t *)phys_to_virt(
            addr & (~PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL)) &
            ~get_physical_memory_offset());
        table_indices[i + 1] = indexs[i + 1];
    }

    // 处理最底层页表
    uint64_t index = table_indices[ARCH_MAX_PT_LEVEL - 1];
    uint64_t pte = table_ptrs[ARCH_MAX_PT_LEVEL - 1][index];

    if ((pte & ARCH_PT_FLAG_VALID) && (pte & ARCH_ADDR_MASK) != 0) {
        uint64_t paddr = pte & ARCH_ADDR_MASK;
        free_frames(paddr, 1);
        table_ptrs[ARCH_MAX_PT_LEVEL - 1][index] = 0;
        arch_flush_tlb(vaddr);

        // 从底层向上检查并释放空页表
        for (int level = ARCH_MAX_PT_LEVEL - 1; level > 0; level--) {
            uint64_t *current_table = table_ptrs[level];
            bool table_empty = true;

            for (uint64_t i = 0; i < 512; i++) {
                if (current_table[i] != 0) {
                    table_empty = false;
                    break;
                }
            }

            if (table_empty) {
                // 释放空页表
                uint64_t table_phys_addr =
                    virt_to_phys((uint64_t)current_table);
                free_frames(table_phys_addr, 1);

                // 清除上级页表中的对应条目
                uint64_t *parent_table = table_ptrs[level - 1];
                uint64_t parent_index = table_indices[level - 1];
                parent_table[parent_index] = 0;
            } else {
                // 页表不为空，停止向上检查
                break;
            }
        }
    }

    return 0;
}

static page_table_t *copy_page_table_recursive(page_table_t *source_table,
                                               int level, bool all_copy,
                                               bool kernel_space) {
    if (source_table == NULL)
        return NULL;
    if (level == 0) {
        if (kernel_space) {
            return source_table;
        }

        uint64_t frame = alloc_frames(1);
        page_table_t *new_page_table = (page_table_t *)phys_to_virt(frame);
        memcpy(new_page_table, phys_to_virt(source_table)->entries,
               DEFAULT_PAGE_SIZE);
        return new_page_table;
    }

    uint64_t phy_frame = alloc_frames(1);
    page_table_t *new_table = (page_table_t *)phys_to_virt(phy_frame);
    for (uint64_t i = 0;
         i <
#if defined(__x86_64__) || defined(__riscv__)
         (all_copy ? 512 : (level == ARCH_MAX_PT_LEVEL ? 256 : 512));
#else
         512;
#endif
         i++) {
        if (ARCH_PT_IS_LARGE(phys_to_virt(source_table)->entries[i].value)) {
            new_table->entries[i].value =
                phys_to_virt(source_table)->entries[i].value;
            continue;
        }

        page_table_t *source_page_table_next =
            (page_table_t *)(phys_to_virt(source_table)->entries[i].value &
                             ARCH_ADDR_MASK);
        page_table_t *new_page_table = copy_page_table_recursive(
            source_page_table_next, level - 1, all_copy,
            level != ARCH_MAX_PT_LEVEL ? kernel_space : i >= 256);
        new_table->entries[i].value =
            (uint64_t)virt_to_phys((uint64_t)new_page_table) |
            (phys_to_virt(source_table)->entries[i].value & ~ARCH_ADDR_MASK);
    }
    return new_table;
}

static void free_page_table_recursive(page_table_t *table, int level) {
    if (!table)
        return;
    if (level == 0) {
        free_frames((uint64_t)virt_to_phys((uint64_t)table), 1);
        return;
    }

    for (int i = 0; i <
#if defined(__x86_64__) || defined(__riscv__)
                    (level == ARCH_MAX_PT_LEVEL ? 256 : 512);
#else
                    512;
#endif
         i++) {
        page_table_t *page_table_next = (page_table_t *)phys_to_virt(
            table->entries[i].value & ARCH_ADDR_MASK);
        free_page_table_recursive(page_table_next, level - 1);
    }
    free_frames((uint64_t)virt_to_phys((uint64_t)table), 1);
}

task_mm_info_t *clone_page_table(task_mm_info_t *old, uint64_t clone_flags) {
    if ((clone_flags & CLONE_VM) && old) {
        old->ref_count++;
        return old;
    }
    task_mm_info_t *new_mm = (task_mm_info_t *)malloc(sizeof(task_mm_info_t));
    memset(new_mm, 0, sizeof(task_mm_info_t));
    new_mm->page_table_addr = virt_to_phys((uint64_t)copy_page_table_recursive(
        (page_table_t *)old->page_table_addr, ARCH_MAX_PT_LEVEL,
        !!(clone_flags & CLONE_VM), false));
#if defined(__x86_64__) || defined(__riscv__)
    memcpy((uint64_t *)phys_to_virt(new_mm->page_table_addr) + 256,
           (uint64_t *)phys_to_virt(old->page_table_addr) + 256,
           DEFAULT_PAGE_SIZE / 2);
#endif
    new_mm->ref_count = 1;
    vma_manager_copy(&new_mm->task_vma_mgr, &old->task_vma_mgr);
    new_mm->task_vma_mgr.initialized = true;
    new_mm->brk_start = old->brk_start;
    new_mm->brk_current = old->brk_current;
    new_mm->brk_end = old->brk_end;
    return new_mm;
}

void free_page_table(task_mm_info_t *directory) {
    if (--directory->ref_count <= 0) {
        free_page_table_recursive(
            (page_table_t *)phys_to_virt(directory->page_table_addr),
            ARCH_MAX_PT_LEVEL);
        free(directory);
    }
}

void page_table_init() {
#if defined(__aarch64__)
    extern void setup_mair(void);
    setup_mair();
#endif
}
