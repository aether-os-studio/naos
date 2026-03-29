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
    uint64_t pte = pgdir[index];
    if (!(pte & ARCH_PT_FLAG_VALID))
        return 0;

    return ARCH_READ_PTE(pte) +
           (vaddr & PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL));
}

uint64_t *kernel_page_dir = NULL;

uint64_t *get_kernel_page_dir() { return kernel_page_dir; }

static inline void unmap_release_page(uint64_t paddr) {
    if (paddr)
        address_release(paddr);
}

static inline void unmap_release_table(uint64_t table_phys_addr) {
    if (table_phys_addr)
        address_release(table_phys_addr);
}

static inline void unmap_batch_queue_page(unmap_release_batch_t *batch,
                                          uint64_t paddr) {
    if (!batch || !paddr)
        return;

    ASSERT(batch->page_count < UNMAP_RELEASE_BATCH_MAX);
    batch->page_addrs[batch->page_count++] = paddr;
}

static inline void unmap_batch_queue_table(unmap_release_batch_t *batch,
                                           uint64_t table_phys_addr) {
    if (!batch || !table_phys_addr)
        return;

    ASSERT(batch->table_count < UNMAP_RELEASE_TABLE_BATCH_MAX);
    batch->table_addrs[batch->table_count++] = table_phys_addr;
}

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr,
                  uint64_t flags, bool force) {
    ASSERT((vaddr & 0xfff) == 0);
    ASSERT(paddr == (uint64_t)-1 || (paddr & 0xfff) == 0);

    uint64_t indexs[ARCH_MAX_PT_LEVEL] = {0};
    uint64_t *created_parent_tables[ARCH_MAX_PT_LEVEL - 1] = {0};
    uint64_t created_parent_indices[ARCH_MAX_PT_LEVEL - 1] = {0};
    uint64_t created_table_addrs[ARCH_MAX_PT_LEVEL - 1] = {0};
    size_t created_tables = 0;
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            return (uint64_t)-1;
        }

        if (!ARCH_PT_IS_TABLE(addr)) {
            uint64_t a = alloc_frames(1);
            if (a == 0) {
                return a;
            }
            memset((uint64_t *)phys_to_virt(a), 0, PAGE_SIZE);
            pgdir[index] = ARCH_MAKE_PTE(a, ARCH_PT_TABLE_FLAGS
#if !defined(__riscv__) && !defined(__loongarch64__)
                                                | (flags & ARCH_PT_FLAG_USER)
#endif
            );
            created_parent_tables[created_tables] = pgdir;
            created_parent_indices[created_tables] = index;
            created_table_addrs[created_tables] = a;
            created_tables++;
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
    bool had_old_mapping = (pgdir[index] & ARCH_PT_FLAG_VALID) != 0;
    uint64_t old_paddr = 0;
    if (had_old_mapping) {
        if (!force)
            return 0;
        old_paddr = ARCH_READ_PTE(pgdir[index]);
    }

    if (paddr == (uint64_t)-1) {
        uint64_t phys = alloc_frames(1);
        if (phys == 0) {
            printk("Cannot allocate frame\n");
            goto rollback_created_tables;
        }
        memset((void *)phys_to_virt(phys), 0, PAGE_SIZE);
        paddr = phys;
    } else if (paddr && (!had_old_mapping || old_paddr != paddr) &&
               !address_ref(paddr)) {
        goto rollback_created_tables;
    }

    if (had_old_mapping && old_paddr && old_paddr != paddr) {
        address_release(old_paddr);
    }

    pgdir[index] = ARCH_MAKE_PTE(paddr, flags);

    arch_flush_tlb(vaddr);

    return 0;

rollback_created_tables:
    while (created_tables > 0) {
        created_tables--;
        created_parent_tables[created_tables]
                             [created_parent_indices[created_tables]] = 0;
        unmap_release_table(created_table_addrs[created_tables]);
    }
    return (uint64_t)-1;
}

uint64_t unmap_page_defer_release(uint64_t *pgdir, uint64_t vaddr,
                                  unmap_release_batch_t *batch) {
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

    if (paddr != 0) {
        table_ptrs[ARCH_MAX_PT_LEVEL - 1][index] = 0;
        arch_flush_tlb(vaddr);
        if (batch) {
            unmap_batch_queue_page(batch, paddr);
        } else {
            unmap_release_page(paddr);
        }

        // 从最底层页表开始向上检查并释放空页表
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
                if (batch) {
                    unmap_batch_queue_table(batch, table_phys_addr);
                } else {
                    unmap_release_table(table_phys_addr);
                }

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

uint64_t unmap_page(uint64_t *pgdir, uint64_t vaddr) {
    return unmap_page_defer_release(pgdir, vaddr, NULL);
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
            uint64_t old_flags = ARCH_READ_PTE_FLAG(pgdir[index]);
            uint64_t keep_flags = old_flags & ARCH_PT_SOFT_FLAGS;
            uint64_t old_paddr = ARCH_READ_PTE(pgdir[index]);
            uint64_t new_flags = flags | keep_flags;
            pgdir[index] = ARCH_MAKE_HUGE_PTE(old_paddr, new_flags);
            arch_flush_tlb(vaddr);
            return 0;
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return 0;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    if (!(pgdir[index] & ARCH_PT_FLAG_VALID)) {
        return 0;
    }

    uint64_t old_paddr = ARCH_READ_PTE(pgdir[index]);
    uint64_t old_flags = ARCH_READ_PTE_FLAG(pgdir[index]);
    uint64_t keep_flags = old_flags & ARCH_PT_SOFT_FLAGS;
    uint64_t new_flags = flags | keep_flags;
    pgdir[index] = ARCH_MAKE_PTE(old_paddr, new_flags);

    arch_flush_tlb(vaddr);

    return 0;
}

static void free_page_table_recursive(uint64_t *table, int level);

static uint64_t page_table_entry_span(int level) {
    return PAGE_CALC_PAGE_TABLE_SIZE(ARCH_MAX_PT_LEVEL - level + 1);
}

static bool pte_is_writable(uint64_t flags) {
#if defined(__aarch64__)
    return (flags & ARCH_PT_FLAG_READONLY) == 0;
#else
    return (flags & ARCH_PT_FLAG_WRITEABLE) != 0;
#endif
}

static bool vma_is_private_mapping(vma_t *vma) {
    return vma && !(vma->vm_flags & (VMA_SHARED | VMA_SHM | VMA_DEVICE));
}

static uint64_t *copy_page_table_recursive(uint64_t *source_table, int level,
                                           uint64_t base_vaddr,
                                           vma_manager_t *mgr) {
    if (!source_table)
        return NULL;

    uint64_t frame = alloc_frames(1);
    if (!frame)
        return NULL;

    uint64_t *new_table = (uint64_t *)phys_to_virt(frame);
    memset(new_table, 0, PAGE_SIZE);

    uint64_t entries = (1UL << ARCH_PT_OFFSET_PER_LEVEL);
#if defined(__x86_64__) || defined(__riscv__)
    if (level == ARCH_MAX_PT_LEVEL)
        entries >>= 1;
#endif

    for (uint64_t i = 0; i < entries; i++) {
        uint64_t entry = source_table[i];
        uint64_t entry_vaddr = base_vaddr + i * page_table_entry_span(level);
        if (!entry)
            continue;

        if (level == 1) {
            uint64_t flags = ARCH_READ_PTE_FLAG(entry);
            if (!(flags & ARCH_PT_FLAG_VALID)) {
                new_table[i] = entry;
                continue;
            }

            uint64_t paddr = ARCH_READ_PTE(entry);
            bool managed = paddr && address_is_managed(paddr);

            if (managed && !address_ref(paddr)) {
                free_page_table_recursive(new_table, level);
                return NULL;
            }

            if (managed && vma_is_private_mapping(vma_find(mgr, entry_vaddr)) &&
                pte_is_writable(flags)) {
                flags |= ARCH_PT_FLAG_COW;
#if defined(__aarch64__)
                flags |= ARCH_PT_FLAG_READONLY;
#else
                flags &= ~ARCH_PT_FLAG_WRITEABLE;
#endif
                source_table[i] = ARCH_MAKE_PTE(paddr, flags);
                arch_flush_tlb(entry_vaddr);
            }

            new_table[i] = ARCH_MAKE_PTE(paddr, flags);
            continue;
        }

        if (ARCH_PT_IS_TABLE(entry)) {
            uint64_t *child_src =
                (uint64_t *)phys_to_virt(ARCH_READ_PTE(entry));
            uint64_t *child_new = copy_page_table_recursive(
                child_src, level - 1, entry_vaddr, mgr);
            if (!child_new) {
                free_page_table_recursive(new_table, level);
                return NULL;
            }

            new_table[i] = ARCH_MAKE_PTE(virt_to_phys((uint64_t)child_new),
                                         ARCH_READ_PTE_FLAG(entry));
            continue;
        }

        new_table[i] = entry;
    }

    return new_table;
}

static void free_page_table_recursive(uint64_t *table, int level) {
    if (!table)
        return;

    uint64_t table_phys = virt_to_phys((uint64_t)table);
    if (!table_phys)
        return;

    uint64_t entries = (1UL << ARCH_PT_OFFSET_PER_LEVEL);
#if defined(__x86_64__) || defined(__riscv__)
    if (level == ARCH_MAX_PT_LEVEL)
        entries >>= 1;
#endif

    if (level == 1) {
        for (uint64_t i = 0; i < entries; i++) {
            uint64_t pte = table[i];

            uint64_t paddr = ARCH_READ_PTE(pte);
            uint64_t flags = ARCH_READ_PTE_FLAG(pte);
            if (!(flags & ARCH_PT_FLAG_VALID))
                continue;
            if (paddr) {
                address_release(paddr);
            }
        }
    } else {
        for (uint64_t i = 0; i < entries; i++) {
            uint64_t entry = table[i];
            if (!ARCH_PT_IS_TABLE(entry))
                continue;

            uint64_t paddr = ARCH_READ_PTE(entry);

            uint64_t *page_table_next = (uint64_t *)phys_to_virt(paddr);
            free_page_table_recursive(page_table_next, level - 1);
        }
    }

    address_release(table_phys);
}

task_mm_info_t *clone_page_table(task_mm_info_t *old, uint64_t clone_flags) {
    if (!old)
        return NULL;

    vma_manager_t *mgr = &old->task_vma_mgr;

    if (clone_flags & CLONE_VM) {
        spin_lock(&mgr->lock);
        spin_lock(&old->lock);
        old->ref_count++;
        spin_unlock(&old->lock);
        spin_unlock(&mgr->lock);
        return old;
    }

    task_mm_info_t *new_mm = (task_mm_info_t *)malloc(sizeof(task_mm_info_t));
    if (!new_mm)
        return NULL;

    memset(new_mm, 0, sizeof(task_mm_info_t));
    spin_init(&new_mm->lock);

    spin_lock(&mgr->lock);
    spin_lock(&old->lock);

    uint64_t *old_root = (uint64_t *)phys_to_virt(old->page_table_addr);
    uint64_t *new_root =
        copy_page_table_recursive(old_root, ARCH_MAX_PT_LEVEL, 0, mgr);
    if (!new_root) {
        free(new_mm);
        spin_unlock(&old->lock);
        spin_unlock(&mgr->lock);
        return NULL;
    }

#if defined(__x86_64__) || defined(__riscv__)
    memcpy(new_root + ((1UL << ARCH_PT_OFFSET_PER_LEVEL) >> 1),
           old_root + ((1UL << ARCH_PT_OFFSET_PER_LEVEL) >> 1), PAGE_SIZE / 2);
#endif

    new_mm->page_table_addr = virt_to_phys((uint64_t)new_root);
    new_mm->ref_count = 1;

    if (vma_manager_copy(&new_mm->task_vma_mgr, mgr) != 0) {
        free_page_table_recursive(new_root, ARCH_MAX_PT_LEVEL);
        free(new_mm);
        spin_unlock(&old->lock);
        spin_unlock(&mgr->lock);
        return NULL;
    }

    spin_unlock(&old->lock);
    spin_unlock(&mgr->lock);

    new_mm->task_vma_mgr.initialized = mgr->initialized;
    new_mm->brk_start = old->brk_start;
    new_mm->brk_current = old->brk_current;
    new_mm->brk_end = old->brk_end;

    return new_mm;
}

void free_page_table(task_mm_info_t *directory) {
    if (!directory)
        return;

    vma_manager_t *mgr = &directory->task_vma_mgr;
    bool should_free = false;

    spin_lock(&directory->lock);
    if (directory->ref_count <= 0) {
        spin_unlock(&directory->lock);
        return;
    }

    if (--directory->ref_count == 0) {
        should_free = true;
    }
    spin_unlock(&directory->lock);

    if (!should_free) {
        return;
    }

    spin_lock(&mgr->lock);
    vma_manager_exit_cleanup(mgr);
    spin_unlock(&mgr->lock);

    free_page_table_recursive(
        (uint64_t *)phys_to_virt(directory->page_table_addr),
        ARCH_MAX_PT_LEVEL);

    free(directory);
}

void page_table_init() {
#if defined(__aarch64__)
    extern void setup_mair(void);
    setup_mair();
#endif
#if defined(__x86_64__) || defined(__riscv__)
    memset(get_current_page_dir(false), 0, PAGE_SIZE / 2);
#endif
    kernel_page_dir = get_current_page_dir(false);
}

void unmap_release_batch_commit(unmap_release_batch_t *batch) {
    if (!batch)
        return;

    for (size_t i = 0; i < batch->page_count; i++) {
        unmap_release_page(batch->page_addrs[i]);
    }

    for (size_t i = 0; i < batch->table_count; i++) {
        unmap_release_table(batch->table_addrs[i]);
    }

    batch->page_count = 0;
    batch->table_count = 0;
}
