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

static page_fault_result_t map_anon_fault_page(task_t *task, vma_t *vma,
                                               uint64_t vaddr) {
    uint64_t *pgdir =
        (uint64_t *)phys_to_virt(task->arch_context->mm->page_table_addr);
    uint64_t pt_flags = vm_flags_to_pt_flags(vma->vm_flags);
    uint64_t arch_flags = get_arch_page_table_flags(pt_flags);

    map_page(pgdir, vaddr, (uint64_t)-1, arch_flags, true);
    if (!translate_address(pgdir, vaddr))
        return PF_RES_NOMEM;

    return PF_RES_OK;
}

static page_fault_result_t map_file_fault_page(task_t *task, vma_t *vma,
                                               uint64_t vaddr) {
    if (!vma->node)
        return PF_RES_SEGF;

    uint64_t *pgdir =
        (uint64_t *)phys_to_virt(task->arch_context->mm->page_table_addr);
    uint64_t final_pt_flags = vm_flags_to_pt_flags(vma->vm_flags);
    bool need_temp_write = (final_pt_flags & PT_FLAG_W) == 0;
    uint64_t load_pt_flags =
        need_temp_write ? (final_pt_flags | PT_FLAG_W) : final_pt_flags;
    uint64_t load_arch_flags = get_arch_page_table_flags(load_pt_flags);

    map_page(pgdir, vaddr, (uint64_t)-1, load_arch_flags, true);
    if (!translate_address(pgdir, vaddr))
        return PF_RES_NOMEM;

    uint64_t page_off = vaddr - vma->vm_start;
    if ((uint64_t)vma->vm_offset > UINT64_MAX - page_off) {
        unmap_page(pgdir, vaddr);
        return PF_RES_SEGF;
    }
    uint64_t file_off = (uint64_t)vma->vm_offset + page_off;
    uint64_t read_size = vma->vm_end - vaddr;
    if (read_size > DEFAULT_PAGE_SIZE)
        read_size = DEFAULT_PAGE_SIZE;

    fd_t file = {
        .node = vma->node,
        .flags = 0,
        .offset = file_off,
        .close_on_exec = false,
    };
    ssize_t ret = vfs_read_fd(&file, (void *)vaddr, file_off, read_size);
    if (ret < 0) {
        unmap_page(pgdir, vaddr);
        return PF_RES_SEGF;
    }

    if (need_temp_write) {
        uint64_t final_arch_flags = get_arch_page_table_flags(final_pt_flags);
        map_change_attribute(pgdir, vaddr, final_arch_flags);
    }

    return PF_RES_OK;
}

page_fault_result_t handle_page_fault(task_t *task, uint64_t vaddr) {
    if (!task)
        return PF_RES_SEGF;
    if (!vaddr)
        return PF_RES_SEGF;

    vaddr = PADDING_DOWN(vaddr, DEFAULT_PAGE_SIZE);

    uint64_t *pgdir =
        (uint64_t *)phys_to_virt(task->arch_context->mm->page_table_addr);

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

    vma_manager_t *mgr = &task->arch_context->mm->task_vma_mgr;
    vma_t *vma = vma_find(mgr, vaddr);

    if (has_leaf && (flags & ARCH_PT_FLAG_COW)) {
        if (!vma || !(vma->vm_flags & VMA_WRITE))
            return PF_RES_SEGF;
#if defined(__aarch64__)
        flags &= ~ARCH_PT_FLAG_READONLY;
#else
        flags |= ARCH_PT_FLAG_WRITEABLE;
#endif
        flags &= ~ARCH_PT_FLAG_COW;

        if (vma &&
            ((vma->vm_flags & VMA_SHM) || (vma->vm_flags & VMA_DEVICE))) {
            goto ok;
        } else {
            uint64_t new_paddr = alloc_frames(1);
            if (!new_paddr)
                return PF_RES_NOMEM;
            memcpy((void *)phys_to_virt(new_paddr),
                   (const void *)phys_to_virt(paddr), DEFAULT_PAGE_SIZE);
            address_release(paddr);
            paddr = new_paddr;
            flags |= ARCH_PT_FLAG_ALLOC;
        }

    ok:
        pgdir[index] = ARCH_MAKE_PTE(paddr, flags);
        arch_flush_tlb(vaddr);

        return PF_RES_OK;
    }

    if (has_leaf && (flags & ARCH_PT_FLAG_VALID))
        return PF_RES_SEGF;

    if (!vma)
        return PF_RES_SEGF;
    if (!(vma->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC)))
        return PF_RES_SEGF;

    if (vma->vm_type == VMA_TYPE_ANON)
        return map_anon_fault_page(task, vma, vaddr);

    if (vma->vm_type == VMA_TYPE_FILE)
        return map_file_fault_page(task, vma, vaddr);

    return PF_RES_SEGF;
}
