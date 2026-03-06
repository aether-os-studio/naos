#include <mm/fault.h>
#include <mm/page.h>
#include <fs/vfs/vfs.h>

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

typedef struct fault_vma_view {
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t vm_flags;
    uint64_t vm_offset;
    vma_type_t vm_type;
    vfs_node_t node;
} fault_vma_view_t;

static void fault_vma_put(fault_vma_view_t *view) {
    if (!view || !view->node)
        return;
    if (view->node->refcount > 0)
        view->node->refcount--;
    shm_try_reap_by_vnode(view->node);
    view->node = NULL;
}

static bool fault_vma_access_allowed(const fault_vma_view_t *view,
                                     uint64_t fault_flags) {
    if (!view)
        return false;

    if (!(view->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC)))
        return false;

    if (fault_flags & PF_ACCESS_WRITE)
        return (view->vm_flags & VMA_WRITE) != 0;

    if (fault_flags & PF_ACCESS_EXEC)
        return (view->vm_flags & VMA_EXEC) != 0;

    if (fault_flags & PF_ACCESS_READ)
        return (view->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC)) != 0;

    return true;
}

static bool fault_lookup_vma(task_t *task, uint64_t vaddr,
                             fault_vma_view_t *view) {
    if (!task || !task->mm || !view)
        return false;

    memset(view, 0, sizeof(*view));

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    vma_t *vma = vma_find(mgr, vaddr);
    if (!vma) {
        spin_unlock(&mgr->lock);
        return false;
    }

    view->vm_start = vma->vm_start;
    view->vm_end = vma->vm_end;
    view->vm_flags = vma->vm_flags;
    view->vm_offset = vma->vm_offset;
    view->vm_type = vma->vm_type;
    view->node = vma->node;
    if (view->node)
        view->node->refcount++;

    spin_unlock(&mgr->lock);
    return true;
}

static bool fault_vma_still_valid(task_t *task, uint64_t vaddr,
                                  const fault_vma_view_t *view,
                                  uint64_t fault_flags) {
    if (!task || !task->mm || !view)
        return false;

    bool valid = false;
    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);

    vma_t *vma = vma_find(mgr, vaddr);
    if (vma && vma->vm_type == view->vm_type && vma->node == view->node &&
        vaddr >= vma->vm_start && vaddr < vma->vm_end) {
        fault_vma_view_t now = {
            .vm_start = vma->vm_start,
            .vm_end = vma->vm_end,
            .vm_flags = vma->vm_flags,
            .vm_offset = vma->vm_offset,
            .vm_type = vma->vm_type,
            .node = vma->node,
        };
        valid = fault_vma_access_allowed(&now, fault_flags);
    }

    spin_unlock(&mgr->lock);
    return valid;
}

static page_fault_result_t map_anon_fault_page(task_t *task,
                                               const fault_vma_view_t *view,
                                               uint64_t vaddr,
                                               uint64_t fault_flags) {
    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t pt_flags = vm_flags_to_pt_flags(view->vm_flags);
    uint64_t arch_flags = get_arch_page_table_flags(pt_flags);

    map_page(pgdir, vaddr, (uint64_t)-1, arch_flags, true);
    if (!translate_address(pgdir, vaddr))
        return PF_RES_NOMEM;

    if (!fault_vma_still_valid(task, vaddr, view, fault_flags)) {
        unmap_page(pgdir, vaddr);
        return PF_RES_SEGF;
    }

    return PF_RES_OK;
}

static page_fault_result_t map_file_fault_page(task_t *task,
                                               const fault_vma_view_t *view,
                                               uint64_t vaddr,
                                               uint64_t fault_flags) {
    if (!view->node)
        return PF_RES_SEGF;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t final_pt_flags = vm_flags_to_pt_flags(view->vm_flags);
    bool need_temp_write = (final_pt_flags & PT_FLAG_W) == 0;
    uint64_t load_pt_flags =
        need_temp_write ? (final_pt_flags | PT_FLAG_W) : final_pt_flags;
    uint64_t load_arch_flags = get_arch_page_table_flags(load_pt_flags);

    map_page(pgdir, vaddr, (uint64_t)-1, load_arch_flags, true);
    if (!translate_address(pgdir, vaddr))
        return PF_RES_NOMEM;

    uint64_t page_off = vaddr - view->vm_start;
    if ((uint64_t)view->vm_offset > UINT64_MAX - page_off) {
        unmap_page(pgdir, vaddr);
        return PF_RES_SEGF;
    }
    uint64_t file_off = (uint64_t)view->vm_offset + page_off;
    uint64_t read_size = view->vm_end - vaddr;
    if (read_size > DEFAULT_PAGE_SIZE)
        read_size = DEFAULT_PAGE_SIZE;

    fd_t file = {
        .node = view->node,
        .flags = 0,
        .offset = file_off,
        .close_on_exec = false,
    };
    ssize_t ret = vfs_read_fd(&file, (void *)vaddr, file_off, read_size);
    if (ret < 0) {
        unmap_page(pgdir, vaddr);
        return ret == -ENOMEM ? PF_RES_NOMEM : PF_RES_SEGF;
    }

    if (need_temp_write) {
        uint64_t final_arch_flags = get_arch_page_table_flags(final_pt_flags);
        map_change_attribute(pgdir, vaddr, final_arch_flags);
    }

    if (!fault_vma_still_valid(task, vaddr, view, fault_flags)) {
        unmap_page(pgdir, vaddr);
        return PF_RES_SEGF;
    }

    return PF_RES_OK;
}

page_fault_result_t handle_page_fault_ex(task_t *task, uint64_t vaddr,
                                         uint64_t fault_flags) {
    if (!task)
        return PF_RES_SEGF;
    if (!vaddr)
        return PF_RES_SEGF;

    vaddr = PADDING_DOWN(vaddr, DEFAULT_PAGE_SIZE);

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);

    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, i + 1);
    }

    bool has_leaf = true;
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
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

    fault_vma_view_t vma;
    bool has_vma = fault_lookup_vma(task, vaddr, &vma);

    if (!has_vma)
        return PF_RES_SEGF;
    if (!fault_vma_access_allowed(&vma, fault_flags)) {
        fault_vma_put(&vma);
        return PF_RES_SEGF;
    }

    if (has_leaf && (flags & ARCH_PT_FLAG_COW)) {
        if ((fault_flags & PF_ACCESS_WRITE) == 0 ||
            !(vma.vm_flags & VMA_WRITE)) {
            fault_vma_put(&vma);
            return PF_RES_SEGF;
        }
#if defined(__aarch64__)
        flags &= ~ARCH_PT_FLAG_READONLY;
#else
        flags |= ARCH_PT_FLAG_WRITEABLE;
#endif
        flags &= ~ARCH_PT_FLAG_COW;

        if ((vma.vm_flags & VMA_SHM) || (vma.vm_flags & VMA_DEVICE)) {
            goto ok;
        } else {
            uint64_t new_paddr = alloc_frames(1);
            if (!new_paddr) {
                fault_vma_put(&vma);
                return PF_RES_NOMEM;
            }
            memcpy((void *)phys_to_virt(new_paddr),
                   (const void *)phys_to_virt(paddr), DEFAULT_PAGE_SIZE);
            address_release(paddr);
            paddr = new_paddr;
            flags |= ARCH_PT_FLAG_ALLOC;
        }

    ok:
        pgdir[index] = ARCH_MAKE_PTE(paddr, flags);
        arch_flush_tlb(vaddr);

        fault_vma_put(&vma);
        return PF_RES_OK;
    }

    if (has_leaf && (flags & ARCH_PT_FLAG_VALID)) {
        fault_vma_put(&vma);
        return PF_RES_SEGF;
    }

    page_fault_result_t ret = PF_RES_SEGF;
    if (vma.vm_type == VMA_TYPE_ANON)
        ret = map_anon_fault_page(task, &vma, vaddr, fault_flags);
    else if (vma.vm_type == VMA_TYPE_FILE)
        ret = map_file_fault_page(task, &vma, vaddr, fault_flags);

    fault_vma_put(&vma);
    return ret;
}

page_fault_result_t handle_page_fault(task_t *task, uint64_t vaddr) {
    return handle_page_fault_ex(task, vaddr, 0);
}
