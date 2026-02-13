#include <arch/arch.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <task/task.h>

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
            return (ARCH_READ_PTE(pgdir[index]) &
                    ~PAGE_CALC_PAGE_TABLE_MASK(i + 1)) +
                   (vaddr & PAGE_CALC_PAGE_TABLE_MASK(i + 1));
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    return ARCH_READ_PTE(pgdir[index]) +
           (vaddr & PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL));
}

uint64_t *kernel_page_dir = NULL;

uint64_t *get_kernel_page_dir() { return kernel_page_dir; }

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr,
                  uint64_t flags, bool force) {
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

        if (!ARCH_PT_IS_TABLE(addr)) {
            uint64_t a = alloc_frames(1);
            if (a == 0) {
                return a;
            }
            memset((uint64_t *)phys_to_virt(a), 0, DEFAULT_PAGE_SIZE);
            pgdir[index] = ARCH_MAKE_PTE(a, ARCH_PT_TABLE_FLAGS
#if !defined(__riscv__) && !defined(__loongarch64__)
                                                | (flags & ARCH_PT_FLAG_USER)
#endif
            );
        }
#if !defined(__riscv__) && !defined(__loongarch64__)
        else {
            if ((flags & ARCH_PT_FLAG_USER) && !(addr & ARCH_PT_FLAG_USER)) {
                uint64_t pa = ARCH_READ_PTE(addr);
                uint64_t old_flags = ARCH_READ_PTE_FLAG(addr);
                pgdir[index] = ARCH_MAKE_PTE(pa, old_flags | ARCH_PT_FLAG_USER);
                arch_flush_tlb(vaddr);
            }
        }
#endif

        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(pgdir[index]));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    if (pgdir[index] & ARCH_PT_FLAG_VALID) {
        if (force) {
            uint64_t paddr = ARCH_READ_PTE(pgdir[index]);
            // free_frames(paddr, 1);
        } else
            return 0;
    }

    if (!paddr) {
        uint64_t phys = alloc_frames(1);
        if (phys == 0) {
            printk("Cannot allocate frame\n");
            return (uint64_t)-1;
        }
        memset((void *)phys_to_virt(phys), 0, DEFAULT_PAGE_SIZE);
        pgdir[index] = ARCH_MAKE_PTE(phys, flags | ARCH_PT_FLAG_ALLOC);
    } else {
        pgdir[index] = ARCH_MAKE_PTE(paddr, flags);
    }

    arch_flush_tlb(vaddr);

    return 0;
}

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
        table_ptrs[i + 1] = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
        table_indices[i + 1] = indexs[i + 1];
    }

    // 处理最底层页表
    uint64_t index = table_indices[ARCH_MAX_PT_LEVEL - 1];
    uint64_t pte = table_ptrs[ARCH_MAX_PT_LEVEL - 1][index];
    uint64_t paddr = ARCH_READ_PTE(pte);
    uint64_t flags = ARCH_READ_PTE_FLAG(pte);

    if (paddr != 0) {
        table_ptrs[ARCH_MAX_PT_LEVEL - 1][index] = 0;
        arch_flush_tlb(vaddr);
        if (flags & ARCH_PT_FLAG_ALLOC) {
            address_unref(paddr);
            if (address_can_free(paddr)) {
                free_frames(paddr, 1);
            }
        }

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

    return paddr;
}

uint64_t map_change_attribute(uint64_t *pgdir, uint64_t vaddr, uint64_t flags) {
    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            pgdir[index] =
                ARCH_MAKE_HUGE_PTE(ARCH_READ_PTE(pgdir[index]), flags);
            arch_flush_tlb(vaddr);
            return 0;
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    pgdir[index] = ARCH_MAKE_PTE(ARCH_READ_PTE(pgdir[index]), flags);

    arch_flush_tlb(vaddr);

    return 0;
}

static uint64_t *copy_page_table_recursive(uint64_t *source_table, int level) {
    if (source_table == NULL)
        return NULL;

    uint64_t phy_frame = alloc_frames(1);
    uint64_t *new_table = (uint64_t *)phys_to_virt(phy_frame);
    memset(new_table, 0, DEFAULT_PAGE_SIZE);
    for (uint64_t i = 0; i <
#if defined(__x86_64__) || defined(__riscv__)
                         (level == ARCH_MAX_PT_LEVEL ? 256 : 512)
#else
                         512
#endif
             ;
         i++) {
        if (ARCH_PT_IS_LARGE(phys_to_virt(source_table)[i]) && level != 1) {
            new_table[i] = phys_to_virt(source_table)[i];
            continue;
        }

        if (level == 1) {
            if (phys_to_virt(source_table)[i] & ARCH_PT_FLAG_VALID) {
                uint64_t flags =
                    ARCH_READ_PTE_FLAG(phys_to_virt(source_table)[i]);
                uint64_t paddr = ARCH_READ_PTE(phys_to_virt(source_table)[i]);
                uint64_t new_paddr = alloc_frames(1);
                memcpy((void *)phys_to_virt(new_paddr),
                       (void *)phys_to_virt(paddr), DEFAULT_PAGE_SIZE);
                flags |= ARCH_PT_FLAG_COW;
#if defined(__aarch64__)
                flags |= ARCH_PT_FLAG_READONLY;
#else
                flags &= ~ARCH_PT_FLAG_WRITEABLE;
#endif
                new_table[i] = ARCH_MAKE_PTE(new_paddr, flags);
                address_ref(new_paddr);
                phys_to_virt(source_table)[i] = ARCH_MAKE_PTE(new_paddr, flags);
                free_frames(paddr, 1);
            } else {
                new_table[i] = 0;
            }
        } else {
            uint64_t *source_page_table_next =
                (uint64_t *)ARCH_READ_PTE(phys_to_virt(source_table)[i]);
            uint64_t flags = ARCH_READ_PTE_FLAG(phys_to_virt(source_table)[i]);

            uint64_t *new_page_table =
                copy_page_table_recursive(source_page_table_next, level - 1);

            if (new_page_table) {
                uint64_t paddr = virt_to_phys((uint64_t)new_page_table);
                new_table[i] = ARCH_MAKE_PTE(paddr, flags);
            } else {
                new_table[i] = 0;
            }
        }
    }
    return new_table;
}

static void free_page_table_recursive(uint64_t *table, int level) {
    if (!virt_to_phys((uint64_t)table))
        return;
    if (level == 0) {
        free_frames((uint64_t)virt_to_phys((uint64_t)table), 1);
        return;
    }

    for (int i = 0; i <
#if defined(__x86_64__) || defined(__riscv__)
                    (level == ARCH_MAX_PT_LEVEL ? 256 : 512)
#else
                    512
#endif
             ;
         i++) {
        uint64_t *page_table_next =
            (uint64_t *)phys_to_virt(ARCH_READ_PTE(table[i]));
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
        (uint64_t *)old->page_table_addr, ARCH_MAX_PT_LEVEL));
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
            (uint64_t *)phys_to_virt(directory->page_table_addr),
            ARCH_MAX_PT_LEVEL);
        free(directory);
    }
}

void page_table_init() {
#if defined(__aarch64__)
    extern void setup_mair(void);
    setup_mair();
#endif
#if defined(__x86_64__) || defined(__riscv__)
    memset(get_current_page_dir(false), 0, DEFAULT_PAGE_SIZE / 2);
#endif
    kernel_page_dir = get_current_page_dir(false);
}
