#include <mm/fault.h>
#include <mm/page.h>
#include <mm/shm.h>
#include <fs/vfs/vfs.h>

typedef struct fault_vma_snapshot {
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t vm_flags;
    vma_type_t vm_type;
    vfs_node_t *node;
    int64_t vm_offset;
    uint64_t vm_file_flags;
} fault_vma_snapshot_t;

static bool fault_vma_snapshot_capture(vma_t *vma,
                                       fault_vma_snapshot_t *snapshot,
                                       bool pin_node) {
    if (!vma || !snapshot)
        return false;

    *snapshot = (fault_vma_snapshot_t){
        .vm_start = vma->vm_start,
        .vm_end = vma->vm_end,
        .vm_flags = vma->vm_flags,
        .vm_type = vma->vm_type,
        .node = vma->node,
        .vm_offset = vma->vm_offset,
        .vm_file_flags = vma->vm_file_flags,
    };

    if (pin_node && snapshot->node)
        vfs_node_ref_get(snapshot->node);

    return true;
}

static bool fault_vma_has_access(const fault_vma_snapshot_t *snapshot) {
    return snapshot && (snapshot->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC));
}

static bool fault_snapshot_allows_access(const fault_vma_snapshot_t *snapshot,
                                         uint64_t fault_flags) {
    if (!fault_vma_has_access(snapshot))
        return false;

    if (fault_flags & PF_ACCESS_EXEC)
        return (snapshot->vm_flags & VMA_EXEC) != 0;
    if (fault_flags & PF_ACCESS_WRITE)
        return (snapshot->vm_flags & VMA_WRITE) != 0;

    return (snapshot->vm_flags & VMA_READ) != 0;
}

static bool fault_vma_allows_access(vma_t *vma, uint64_t fault_flags) {
    if (!vma)
        return false;

    if (!(vma->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC)))
        return false;

    if (fault_flags & PF_ACCESS_EXEC)
        return (vma->vm_flags & VMA_EXEC) != 0;
    if (fault_flags & PF_ACCESS_WRITE)
        return (vma->vm_flags & VMA_WRITE) != 0;

    return (vma->vm_flags & VMA_READ) != 0;
}

static bool fault_vma_can_resolve_cow(const fault_vma_snapshot_t *snapshot) {
    return snapshot && (snapshot->vm_flags & VMA_WRITE) &&
           !(snapshot->vm_flags & (VMA_SHARED | VMA_SHM | VMA_DEVICE));
}

static uint64_t vm_flags_to_pt_flags(uint64_t vm_flags) {
    uint64_t pt_flags = PT_FLAG_U;
    if (vm_flags & VMA_READ)
        pt_flags |= PT_FLAG_R;
    if (vm_flags & VMA_WRITE)
        pt_flags |= PT_FLAG_W;
    if (vm_flags & VMA_EXEC)
        pt_flags |= PT_FLAG_X;
    return pt_flags;
}

static page_fault_result_t map_anon_fault_page(task_t *task, vma_t *vma,
                                               uint64_t vaddr) {
    uint64_t pt_flags = vm_flags_to_pt_flags(vma->vm_flags);
    uint64_t aligned_vaddr = PADDING_DOWN(vaddr, PAGE_SIZE);
    uint64_t *pgdir = NULL;

    spin_lock(&task->mm->lock);
    pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);

    if (translate_address(pgdir, aligned_vaddr)) {
        spin_unlock(&task->mm->lock);
        return PF_RES_OK;
    }

    map_page_range_mm(task->mm, aligned_vaddr, (uint64_t)-1, PAGE_SIZE,
                      pt_flags);

    spin_unlock(&task->mm->lock);

    return PF_RES_OK;
}

static void fault_vma_snapshot_put(fault_vma_snapshot_t *snapshot) {
    if (!snapshot || !snapshot->node)
        return;

    vfs_node_ref_put(snapshot->node, NULL);
    shm_try_reap_by_vnode(snapshot->node);
    snapshot->node = NULL;
}

static bool fault_vma_matches_snapshot(vma_t *vma,
                                       const fault_vma_snapshot_t *snapshot) {
    if (!vma || !snapshot)
        return false;

    return vma->vm_start == snapshot->vm_start &&
           vma->vm_end == snapshot->vm_end &&
           vma->vm_flags == snapshot->vm_flags &&
           vma->vm_type == snapshot->vm_type && vma->node == snapshot->node &&
           vma->vm_offset == snapshot->vm_offset &&
           vma->vm_file_flags == snapshot->vm_file_flags;
}

static page_fault_result_t
map_file_fault_page_snapshot(task_t *task, const fault_vma_snapshot_t *snapshot,
                             uint64_t vaddr, uint64_t fault_flags) {
    if (!task || !snapshot || !snapshot->node)
        return PF_RES_SEGF;

    uint64_t aligned_vaddr = PADDING_DOWN(vaddr, PAGE_SIZE);
    uint64_t final_pt_flags = vm_flags_to_pt_flags(snapshot->vm_flags);
    uint64_t page_off_in_vma = aligned_vaddr - snapshot->vm_start;

    if ((uint64_t)snapshot->vm_offset > UINT64_MAX - page_off_in_vma)
        return PF_RES_SEGF;

    uint64_t file_off = (uint64_t)snapshot->vm_offset + page_off_in_vma;
    uint64_t read_size = snapshot->vm_end - aligned_vaddr;
    if (read_size > PAGE_SIZE)
        read_size = PAGE_SIZE;

    uint64_t page_paddr = alloc_frames(1);
    if (!page_paddr)
        return PF_RES_NOMEM;

    memset((void *)phys_to_virt(page_paddr), 0, PAGE_SIZE);

    size_t loaded = 0;
    fd_shared_t shared = {
        .flags = snapshot->vm_file_flags,
        .offset = file_off,
    };
    fd_t fd = {
        .node = snapshot->node,
        .shared = &shared,
        .close_on_exec = false,
    };
    while (loaded < read_size) {
        ssize_t ret =
            vfs_read_fd(&fd, (void *)(phys_to_virt(page_paddr) + loaded),
                        file_off + loaded, read_size - loaded);
        if (ret < 0) {
            address_release(page_paddr);
            return PF_RES_SEGF;
        }
        if (ret == 0)
            break;
        loaded += (size_t)ret;
    }

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);

    vma_t *current_vma = vma_find(mgr, vaddr);
    if (!fault_vma_matches_snapshot(current_vma, snapshot) ||
        !fault_snapshot_allows_access(snapshot, fault_flags)) {
        spin_unlock(&mgr->lock);
        address_release(page_paddr);
        return PF_RES_SEGF;
    }

    spin_lock(&task->mm->lock);

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    if (translate_address(pgdir, aligned_vaddr)) {
        spin_unlock(&task->mm->lock);
        spin_unlock(&mgr->lock);
        address_release(page_paddr);
        return PF_RES_OK;
    }

    map_page_range_mm(task->mm, aligned_vaddr, page_paddr, PAGE_SIZE,
                      final_pt_flags);

    spin_unlock(&task->mm->lock);
    spin_unlock(&mgr->lock);

    address_release(page_paddr);

    return PF_RES_OK;
}

static page_fault_result_t
map_cow_fault_page_snapshot(task_t *task, const fault_vma_snapshot_t *snapshot,
                            uint64_t vaddr, uint64_t old_paddr) {
    if (!task || !snapshot || !old_paddr)
        return PF_RES_SEGF;
    if (!fault_vma_can_resolve_cow(snapshot))
        return PF_RES_SEGF;

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    vma_t *current_vma = vma_find(mgr, vaddr);
    if (!fault_vma_matches_snapshot(current_vma, snapshot) ||
        !fault_vma_can_resolve_cow(snapshot)) {
        return PF_RES_SEGF;
    }

    spin_lock(&task->mm->lock);

    uint64_t aligned_vaddr = PADDING_DOWN(vaddr, PAGE_SIZE);
    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(aligned_vaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t entry = pgdir[indexs[i]];
        if (!ARCH_PT_IS_TABLE(entry)) {
            spin_unlock(&task->mm->lock);
            return PF_RES_SEGF;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(entry));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    uint64_t current_entry = pgdir[index];
    if (!(current_entry & ARCH_PT_FLAG_COW)) {
        bool already_resolved = (current_entry & ARCH_PT_FLAG_VALID) != 0;
        spin_unlock(&task->mm->lock);
        return already_resolved ? PF_RES_OK : PF_RES_SEGF;
    }

    if (ARCH_READ_PTE(current_entry) != old_paddr) {
        spin_unlock(&task->mm->lock);
        return PF_RES_SEGF;
    }

    if (address_is_managed(old_paddr) &&
        page_refcount_read(get_page(old_paddr)) == 1) {
        uint64_t flags = ARCH_READ_PTE_FLAG(current_entry);
#if defined(__aarch64__)
        flags &= ~ARCH_PT_FLAG_READONLY;
#else
        flags |= ARCH_PT_FLAG_WRITEABLE;
#endif
        flags &= ~ARCH_PT_FLAG_COW;

        pgdir[index] = ARCH_MAKE_PTE(old_paddr, flags);
        arch_flush_tlb(vaddr);

        spin_unlock(&task->mm->lock);
        return PF_RES_OK;
    }

    uint64_t new_paddr = alloc_frames(1);
    if (!new_paddr) {
        spin_unlock(&task->mm->lock);
        return PF_RES_NOMEM;
    }
    memcpy((void *)phys_to_virt(new_paddr),
           (const void *)phys_to_virt(old_paddr), PAGE_SIZE);

    uint64_t flags = ARCH_READ_PTE_FLAG(current_entry);
#if defined(__aarch64__)
    flags &= ~ARCH_PT_FLAG_READONLY;
#else
    flags |= ARCH_PT_FLAG_WRITEABLE;
#endif
    flags &= ~ARCH_PT_FLAG_COW;

    pgdir[index] = ARCH_MAKE_PTE(new_paddr, flags);
    arch_flush_tlb(vaddr);

    spin_unlock(&task->mm->lock);

    address_release(old_paddr);

    return PF_RES_OK;
}

page_fault_result_t handle_page_fault_flags(task_t *task, uint64_t vaddr,
                                            uint64_t fault_flags) {
    if (!task)
        return PF_RES_SEGF;
    if (!vaddr)
        return PF_RES_SEGF;

    uint64_t aligned_vaddr = PADDING_DOWN(vaddr, PAGE_SIZE);

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    spin_lock(&task->mm->lock);

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);

    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(aligned_vaddr, i + 1);
    }

    bool has_leaf = true;
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            spin_unlock(&task->mm->lock);
            spin_unlock(&mgr->lock);
            return PF_RES_SEGF;
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            has_leaf = false;
            break;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];
    uint64_t paddr = 0;
    uint64_t flags = 0;
    if (has_leaf) {
        paddr = ARCH_READ_PTE(pgdir[index]);
        flags = ARCH_READ_PTE_FLAG(pgdir[index]);
    }

    spin_unlock(&task->mm->lock);

    vma_t *vma = vma_find(mgr, vaddr);
    page_fault_result_t result = PF_RES_SEGF;

    if (has_leaf && (flags & ARCH_PT_FLAG_COW)) {
        if (!(fault_flags & PF_ACCESS_WRITE)) {
            spin_unlock(&mgr->lock);
            return PF_RES_SEGF;
        }

        fault_vma_snapshot_t snapshot = {0};
        if (!vma || !fault_vma_snapshot_capture(vma, &snapshot, true) ||
            !fault_vma_can_resolve_cow(&snapshot)) {
            fault_vma_snapshot_put(&snapshot);
            spin_unlock(&mgr->lock);
            return PF_RES_SEGF;
        }

        result = map_cow_fault_page_snapshot(task, &snapshot, vaddr, paddr);
        spin_unlock(&mgr->lock);
        fault_vma_snapshot_put(&snapshot);
        return result;
    }

    if (has_leaf && (flags & ARCH_PT_FLAG_VALID)) {
        spin_unlock(&mgr->lock);
        return PF_RES_SEGF;
    }

    if (!vma) {
        spin_unlock(&mgr->lock);
        return PF_RES_SEGF;
    }
    if (!fault_vma_allows_access(vma, fault_flags)) {
        spin_unlock(&mgr->lock);
        return PF_RES_SEGF;
    }

    if (vma->vm_type == VMA_TYPE_FILE) {
        fault_vma_snapshot_t snapshot = {0};
        fault_vma_snapshot_capture(vma, &snapshot, true);

        spin_unlock(&mgr->lock);
        result =
            map_file_fault_page_snapshot(task, &snapshot, vaddr, fault_flags);
        fault_vma_snapshot_put(&snapshot);
        return result;
    }

    if (vma->vm_type == VMA_TYPE_ANON)
        result = map_anon_fault_page(task, vma, vaddr);

    spin_unlock(&mgr->lock);

    return result;
}
