#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

uint64_t sys_brk(uint64_t brk) {
    brk = (brk + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);

    if (!brk) {
        return current_task->arch_context->mm->brk_start;
    }

    if (brk > current_task->arch_context->mm->brk_current) {
        map_page_range(get_current_page_dir(true),
                       current_task->arch_context->mm->brk_current, 0,
                       brk - current_task->arch_context->mm->brk_current,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

        memset((void *)current_task->arch_context->mm->brk_current, 0,
               brk - current_task->arch_context->mm->brk_current);

        vma_t *vma = vma_alloc();

        vma->vm_start = current_task->arch_context->mm->brk_current;
        vma->vm_end = brk;
        vma->vm_flags = 0;

        vma->vm_flags |= VMA_READ | VMA_WRITE;

        vma->vm_type = VMA_TYPE_ANON;
        vma->vm_flags |= VMA_ANON;
        vma->vm_fd = -1;

        vma->vm_name = strdup("[heap]");

        vma_t *region =
            vma_find_intersection(&current_task->arch_context->mm->task_vma_mgr,
                                  current_task->arch_context->mm->brk_start,
                                  current_task->arch_context->mm->brk_end);

        if (region) {
            vma_remove(&current_task->arch_context->mm->task_vma_mgr, region);
            vma_free(region);
        }

        if (vma_insert(&current_task->arch_context->mm->task_vma_mgr, vma) !=
            0) {
            vma_free(vma);
            return (uint64_t)-ENOMEM;
        }

        current_task->arch_context->mm->brk_current = brk;
    }

    return current_task->arch_context->mm->brk_current;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                  uint64_t fd, uint64_t offset) {
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t aligned_len =
        (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (check_user_overflow(addr, aligned_len)) {
        return -EFAULT;
    }

    if (aligned_len == 0) {
        return (uint64_t)-EINVAL;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    uint64_t start_addr;
    if (flags & MAP_FIXED) {
        if (!addr)
            return (uint64_t)-EINVAL;

        start_addr = (uint64_t)addr;
        // 检查地址是否可用
        if (vma_find_intersection(mgr, start_addr, start_addr + aligned_len)) {
            vma_unmap_range(mgr, start_addr, start_addr + aligned_len);
        }
    } else {
        if (addr) {
            start_addr = (uint64_t)addr;
            // 检查地址是否可用
            if (vma_find_intersection(mgr, start_addr,
                                      start_addr + aligned_len)) {
                return (uint64_t)-ENOMEM;
            }
        } else {
        retry:
            start_addr = mgr->last_alloc_addr;
            while (vma_find_intersection(mgr, start_addr,
                                         start_addr + aligned_len)) {
                start_addr += DEFAULT_PAGE_SIZE;
                if (start_addr > USER_MMAP_END) {
                    if (mgr->last_alloc_addr != USER_MMAP_START) {
                        mgr->last_alloc_addr = USER_MMAP_START;
                        goto retry;
                    }
                    return (uint64_t)-ENOMEM;
                }
            }
        }
    }

    if (!(flags & MAP_ANONYMOUS)) {
        if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
            return (uint64_t)-EBADF;
    }

    vma_t *vma = vma_alloc();
    if (!vma)
        return (uint64_t)-ENOMEM;

    vma->vm_start = start_addr;
    vma->vm_end = start_addr + aligned_len;
    vma->vm_flags = 0;

    if (prot & PROT_READ)
        vma->vm_flags |= VMA_READ;
    if (prot & PROT_WRITE)
        vma->vm_flags |= VMA_WRITE;
    if (prot & PROT_EXEC)
        vma->vm_flags |= VMA_EXEC;
    if (flags & MAP_SHARED)
        vma->vm_flags |= VMA_SHARED;

    if (flags & MAP_ANONYMOUS) {
        vma->vm_type = VMA_TYPE_ANON;
        vma->vm_flags |= VMA_ANON;
        vma->vm_fd = -1;
    } else {
        vma->vm_type = VMA_TYPE_FILE;
        vma->vm_fd = fd;
        vma->vm_offset = offset;
    }

    vma_t *region =
        vma_find_intersection(mgr, start_addr, start_addr + aligned_len);
    if (region) {
        vma_remove(mgr, region);
        vma_free(region);
    }

    if (vma_insert(mgr, vma) != 0) {
        vma_free(vma);
        return (uint64_t)-ENOMEM;
    }

    if (!addr)
        mgr->last_alloc_addr = start_addr;

    if (!(flags & MAP_ANONYMOUS)) {
        uint64_t ret =
            (uint64_t)vfs_map(current_task->fd_info->fds[fd], start_addr,
                              aligned_len, prot, flags, offset);

        region->vm_name =
            vfs_get_fullpath(current_task->fd_info->fds[fd]->node);
        return ret;
    } else {
        uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

        if (prot != PROT_NONE) {
            if (prot & PROT_READ)
                pt_flags |= PT_FLAG_R;
            if (prot & PROT_WRITE)
                pt_flags |= PT_FLAG_W;
            if (prot & PROT_EXEC)
                pt_flags |= PT_FLAG_X;
        }

        map_page_range(get_current_page_dir(true), start_addr, 0, aligned_len,
                       pt_flags);

        memset((void *)start_addr, 0, aligned_len);

        return start_addr;
    }
}

uint64_t sys_munmap(uint64_t addr, uint64_t size) {
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    size = (size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);

    if (check_user_overflow(addr, size)) {
        return -EFAULT;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    vma_t *vma = mgr->vma_list;
    vma_t *next;

    uint64_t start = addr;
    uint64_t end = addr + size;

    while (vma) {
        next = vma->vm_next;

        // 完全包含在要取消映射的范围内
        if (vma->vm_start >= start && vma->vm_end <= end) {
            vma_remove(mgr, vma);
            vma_free(vma);
        }
        // 部分重叠 - 需要分割
        else if (!(vma->vm_end <= start || vma->vm_start >= end)) {
            if (vma->vm_start < start && vma->vm_end > end) {
                // VMA跨越整个取消映射范围 - 分割成两部分
                vma_split(vma, end);
                vma_split(vma, start);
                // 移除中间部分
                vma_t *middle = vma->vm_next;
                vma_remove(mgr, middle);
                vma_free(middle);
            } else if (vma->vm_start < start) {
                // 截断VMA的末尾
                vma->vm_end = start;
            } else if (vma->vm_end > end) {
                // 截断VMA的开头
                vma->vm_start = end;
                if (vma->vm_type == VMA_TYPE_FILE) {
                    vma->vm_offset += end - vma->vm_start;
                }
            }
        }

        vma = next;
    }

    unmap_page_range(get_current_page_dir(true), start, end - start);
    return 0;
}

uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (check_user_overflow(addr, len)) {
        return -EFAULT;
    }

    uint64_t pt_flags = PT_FLAG_U;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_change_attribute_range(
        get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)),
        (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    return 0;
}

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr) {
    old_addr = old_addr & (~(DEFAULT_PAGE_SIZE - 1));
    new_addr = new_addr & (~(DEFAULT_PAGE_SIZE - 1));
    old_size = (old_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    new_size = (new_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    vma_t *vma = vma_find(mgr, (unsigned long)old_addr);
    if (!vma || vma->vm_start != (unsigned long)old_addr) {
        return (uint64_t)-EINVAL;
    }

    uint64_t old_addr_phys =
        translate_address(get_current_page_dir(true), old_addr);

    // 如果新大小更小，直接截断
    if (new_size <= vma->vm_end - vma->vm_start) {
        unmap_page_range(get_current_page_dir(true), vma->vm_end,
                         vma->vm_start + new_size - vma->vm_end);
        vma->vm_end = vma->vm_start + new_size;
        return old_addr;
    }

    // 如果需要扩大，检查是否有足够空间
    uint64_t new_end = vma->vm_start + new_size;
    if (!vma_find_intersection(mgr, vma->vm_end, new_end)) {
        uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

        if (vma->vm_flags & VMA_READ)
            pt_flags |= PT_FLAG_R;
        if (vma->vm_flags & VMA_WRITE)
            pt_flags |= PT_FLAG_W;
        if (vma->vm_flags & VMA_EXEC)
            pt_flags |= PT_FLAG_X;

        map_page_range(get_current_page_dir(true), vma->vm_end,
                       old_addr_phys + vma->vm_end - vma->vm_start,
                       new_end - vma->vm_end, vma->vm_flags);

        vma->vm_end = new_end;
        return old_addr;
    }

    if (flags & MREMAP_MAYMOVE) {
    retry:
        uint64_t start_addr = mgr->last_alloc_addr;
        while (vma_find_intersection(mgr, start_addr, start_addr + new_size)) {
            start_addr += DEFAULT_PAGE_SIZE;
            if (start_addr > USER_MMAP_END) {
                if (mgr->last_alloc_addr != USER_MMAP_START) {
                    mgr->last_alloc_addr = USER_MMAP_START;
                    goto retry;
                }
                return (uint64_t)-ENOMEM;
            }
        }

        vma_t *new_vma = vma_alloc();
        if (!new_vma)
            return (uint64_t)-ENOMEM;

        memcpy(new_vma, vma, sizeof(vma_t));
        new_vma->vm_start = start_addr;
        new_vma->vm_end = start_addr + new_size;
        new_vma->vm_flags = 0;

        if (vma_insert(mgr, new_vma) != 0) {
            vma_free(new_vma);
            return (uint64_t)-ENOMEM;
        }

        uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

        if (new_vma->vm_flags & VMA_READ)
            pt_flags |= PT_FLAG_R;
        if (new_vma->vm_flags & VMA_WRITE)
            pt_flags |= PT_FLAG_W;
        if (new_vma->vm_flags & VMA_EXEC)
            pt_flags |= PT_FLAG_X;

        mgr->last_alloc_addr = start_addr;

        map_page_range(get_current_page_dir(true), start_addr, old_addr_phys,
                       new_size, pt_flags);

        sys_munmap(old_addr, old_size);

        return start_addr;
    }

    return (uint64_t)-ENOMEM;
}

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset) {
    uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_page_range(
        get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), 0,
        (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    ssize_t ret = vfs_read_fd(file, (void *)addr, offset, len);
    if (ret < 0) {
        printk("Failed read file for mmap\n");
        return (void *)ret;
    }

    return (void *)addr;
}

uint64_t sys_msync(uint64_t addr, uint64_t size, uint64_t flags) { return 0; }

uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec) {
    if (check_user_overflow(addr, size)) {
        return -EFAULT;
    }

    if (size == 0) {
        return 0;
    }

    uint64_t start_page = addr & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t end_page = (addr + size - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t num_pages = ((end_page - start_page) / DEFAULT_PAGE_SIZE) + 1;

    if (check_user_overflow(vec, num_pages)) {
        return -EFAULT;
    }

    uint64_t *page_dir = get_current_page_dir(true);
    uint64_t current_addr = start_page;

    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t phys_addr = translate_address(page_dir, current_addr);

        uint8_t resident = (phys_addr != 0) ? 1 : 0;

        memcpy((void *)(vec + i), &resident, sizeof(uint8_t));

        current_addr += DEFAULT_PAGE_SIZE;
    }

    return 0;
}
