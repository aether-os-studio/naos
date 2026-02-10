#include <mm/fault.h>
#include <mm/page.h>
#include <fs/vfs/vfs.h>

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

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t index = indexs[i];
        uint64_t addr = pgdir[index];
        if (ARCH_PT_IS_LARGE(addr)) {
            return PF_RES_SEGF;
        }
        if (!ARCH_PT_IS_TABLE(addr)) {
            return PF_RES_SEGF;
        }
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(addr));
    }

    uint64_t index = indexs[ARCH_MAX_PT_LEVEL - 1];

    uint64_t paddr = ARCH_READ_PTE(pgdir[index]);
    uint64_t flags = ARCH_READ_PTE_FLAG(pgdir[index]);

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    if (flags & ARCH_PT_FLAG_COW) {
#if defined(__aarch64__)
        flags &= ~ARCH_PT_FLAG_READONLY;
#else
        flags |= ARCH_PT_FLAG_WRITEABLE;
#endif
        // flags &= ~ARCH_PT_FLAG_COW;

        vma_t *vma =
            vma_find_intersection(mgr, vaddr, vaddr + DEFAULT_PAGE_SIZE);

        if (vma &&
            ((vma->vm_flags & VMA_SHM) || (vma->vm_flags & VMA_DEVICE))) {
            goto ok;
        } else {
            uint64_t new_paddr = alloc_frames(1);
            if (!new_paddr)
                return PF_RES_NOMEM;
            memcpy((void *)phys_to_virt(new_paddr),
                   (const void *)phys_to_virt(paddr), DEFAULT_PAGE_SIZE);
            address_unref(paddr);
            paddr = new_paddr;
        }

    ok:
        pgdir[index] = ARCH_MAKE_PTE(paddr, flags);
        arch_flush_tlb(vaddr);

        return PF_RES_OK;
    }

    return PF_RES_SEGF;
}
