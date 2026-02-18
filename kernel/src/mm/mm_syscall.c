#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

uint64_t do_munmap(uint64_t addr, uint64_t size);

static uint64_t find_unmapped_area_in_window(vma_manager_t *mgr,
                                             uint64_t window_start,
                                             uint64_t window_end,
                                             uint64_t len) {
    window_start = PADDING_UP(window_start, DEFAULT_PAGE_SIZE);
    window_end = PADDING_DOWN(window_end, DEFAULT_PAGE_SIZE);

    if (window_start >= window_end)
        return (uint64_t)-ENOMEM;
    if (len > window_end - window_start)
        return (uint64_t)-ENOMEM;

    uint64_t cursor = window_start;
    rb_node_t *node = rb_first(&mgr->vma_tree);

    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        node = rb_next(node);

        if (vma->vm_end <= cursor)
            continue;
        if (vma->vm_start >= window_end)
            break;

        uint64_t gap_end =
            vma->vm_start < window_end ? vma->vm_start : window_end;
        if (gap_end > cursor && gap_end - cursor >= len)
            return cursor;

        if (vma->vm_end > cursor)
            cursor = PADDING_UP(vma->vm_end, DEFAULT_PAGE_SIZE);

        if (cursor > window_end - len)
            return (uint64_t)-ENOMEM;
    }

    if (window_end - cursor >= len)
        return cursor;
    return (uint64_t)-ENOMEM;
}

static uint64_t find_unmapped_area(vma_manager_t *mgr, uint64_t hint,
                                   uint64_t len) {
    if (len == 0 || len > USER_MMAP_END - USER_MMAP_START) {
        return (uint64_t)-ENOMEM;
    }

    len = PADDING_UP(len, DEFAULT_PAGE_SIZE);

    if (hint) {
        hint = PADDING_UP(hint, DEFAULT_PAGE_SIZE);
        if (hint >= USER_MMAP_START && hint <= USER_MMAP_END - len) {
            if (!vma_find_intersection(mgr, hint, hint + len))
                return hint;

            uint64_t up =
                find_unmapped_area_in_window(mgr, hint, USER_MMAP_END, len);
            if (up < (uint64_t)-4095UL)
                return up;

            if (hint > USER_MMAP_START) {
                uint64_t wrap = find_unmapped_area_in_window(
                    mgr, USER_MMAP_START, hint, len);
                if (wrap < (uint64_t)-4095UL)
                    return wrap;
            }
        }
    }

    return find_unmapped_area_in_window(mgr, USER_MMAP_START, USER_MMAP_END,
                                        len);
}

static int mmap_check_flags_linux(uint64_t flags, uint64_t map_type) {
    const uint64_t supported_flags =
        MAP_TYPE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_GROWSDOWN |
        MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED | MAP_POPULATE |
        MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE;

    uint64_t unknown = flags & ~supported_flags;
    if (unknown && map_type == MAP_SHARED_VALIDATE)
        return -EOPNOTSUPP;

    if (flags & MAP_SYNC) {
        if (map_type != MAP_SHARED_VALIDATE)
            return -EINVAL;
    }

    return 0;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                  uint64_t fd, uint64_t offset) {
    const uint64_t passthrough_flags =
        MAP_TYPE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_GROWSDOWN |
        MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED | MAP_POPULATE |
        MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE;

    uint64_t aligned_len = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    uint64_t page_mask = DEFAULT_PAGE_SIZE - 1;
    uint64_t map_type = flags & MAP_TYPE;
    uint64_t clean_flags = flags & passthrough_flags;
    bool fixed_map = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;

    if (len == 0 || aligned_len == 0)
        return (uint64_t)-EINVAL;

    if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
        return (uint64_t)-EINVAL;

    if (map_type != MAP_PRIVATE && map_type != MAP_SHARED &&
        map_type != MAP_SHARED_VALIDATE)
        return (uint64_t)-EINVAL;

    int flag_ret = mmap_check_flags_linux(flags, map_type);
    if (flag_ret < 0)
        return (uint64_t)flag_ret;

    if (offset & page_mask)
        return (uint64_t)-EINVAL;
    if ((flags & MAP_ANONYMOUS) && offset != 0)
        return (uint64_t)-EINVAL;
    if ((flags & MAP_SYNC) && (flags & MAP_ANONYMOUS))
        return (uint64_t)-EINVAL;

    fd_t *map_fd = NULL;
    vfs_node_t map_node = NULL;
    if (!(flags & MAP_ANONYMOUS)) {
        if (fd >= MAX_FD_NUM)
            return (uint64_t)-EBADF;

        map_fd = current_task->fd_info->fds[fd];
        if (!map_fd || !map_fd->node)
            return (uint64_t)-EBADF;

        map_node = map_fd->node;
        if (map_node->type & file_dir)
            return (uint64_t)-EISDIR;

        uint64_t acc_mode = map_fd->flags & O_ACCMODE_FLAGS;
        if ((prot & (PROT_READ | PROT_EXEC)) && acc_mode == O_WRONLY)
            return (uint64_t)-EACCES;
        if ((prot & PROT_WRITE) &&
            (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE) &&
            acc_mode == O_RDONLY) {
            return (uint64_t)-EACCES;
        }

        if (flags & MAP_SYNC)
            return (uint64_t)-EOPNOTSUPP;
    }

    uint64_t start_addr = 0;
    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    spin_lock(&mgr->lock);

    if (fixed_map) {
        if (addr & page_mask) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-EINVAL;
        }
        if (check_user_overflow(addr, aligned_len)) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }

        start_addr = addr;

        if (vma_find_intersection(mgr, start_addr, start_addr + aligned_len)) {
            if (flags & MAP_FIXED_NOREPLACE) {
                spin_unlock(&mgr->lock);
                return (uint64_t)-EEXIST;
            }

            uint64_t unmap_ret = do_munmap(start_addr, aligned_len);
            if ((int64_t)unmap_ret < 0) {
                spin_unlock(&mgr->lock);
                return unmap_ret;
            }
        }
    } else {
        uint64_t hint = addr ? PADDING_UP(addr, DEFAULT_PAGE_SIZE) : 0;
        start_addr = find_unmapped_area(mgr, hint, aligned_len);
        if (start_addr > (uint64_t)-4095UL) {
            spin_unlock(&mgr->lock);
            return start_addr;
        }
    }

    vma_t *vma = vma_alloc();
    if (!vma) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    vma->vm_start = start_addr;
    vma->vm_end = start_addr + aligned_len;
    vma->vm_flags = 0;
    if (prot & PROT_READ)
        vma->vm_flags |= VMA_READ;
    if (prot & PROT_WRITE)
        vma->vm_flags |= VMA_WRITE;
    if (prot & PROT_EXEC)
        vma->vm_flags |= VMA_EXEC;
    if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
        vma->vm_flags |= VMA_SHARED;

    if (flags & MAP_ANONYMOUS) {
        vma->vm_type = VMA_TYPE_ANON;
        vma->vm_flags |= VMA_ANON;
    } else {
        vma->vm_type = VMA_TYPE_FILE;
        vma->node = map_node;
        vma->vm_offset = offset;
        map_node->refcount++;

        char *fullpath = vfs_get_fullpath(map_node);
        if (fullpath) {
            vma->vm_name = strdup(fullpath);
            free(fullpath);
            if (!vma->vm_name) {
                spin_unlock(&mgr->lock);
                vma_free(vma);
                return (uint64_t)-ENOMEM;
            }
        }

        if ((map_node->type & file_stream) || (map_node->type & file_block))
            vma->vm_flags |= VMA_DEVICE;
    }

    if (vma_insert(mgr, vma) != 0) {
        spin_unlock(&mgr->lock);
        vma_free(vma);
        return (uint64_t)-ENOMEM;
    }

    spin_unlock(&mgr->lock);

    uint64_t ret;
    if (flags & MAP_ANONYMOUS) {
        uint64_t pt_flags = PT_FLAG_U;
        if (prot & PROT_READ)
            pt_flags |= PT_FLAG_R;
        if (prot & PROT_WRITE)
            pt_flags |= PT_FLAG_W;
        if (prot & PROT_EXEC)
            pt_flags |= PT_FLAG_X;

        map_page_range(get_current_page_dir(true), start_addr, (uint64_t)-1,
                       aligned_len, pt_flags);

        ret = start_addr;
    } else {
        ret = (uint64_t)vfs_map(map_fd, start_addr, aligned_len, prot,
                                clean_flags, offset);
        if ((int64_t)ret >= 0)
            ret = start_addr;
    }

    if ((int64_t)ret < 0) {
        unmap_page_range(get_current_page_dir(true), start_addr, aligned_len);
        spin_lock(&mgr->lock);
        vma_remove(mgr, vma);
        spin_unlock(&mgr->lock);
        vma_free(vma);
        return ret;
    }

    return ret;
}

uint64_t do_munmap(uint64_t addr, uint64_t size) {
    addr = PADDING_DOWN(addr, DEFAULT_PAGE_SIZE);
    size = PADDING_UP(size, DEFAULT_PAGE_SIZE);

    if (size == 0)
        return (uint64_t)-EINVAL;
    if (check_user_overflow(addr, size))
        return (uint64_t)-EFAULT;

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    uint64_t start = addr;
    uint64_t end = addr + size;
    uint64_t *pgdir = get_current_page_dir(true);

    while (true) {
        vma_t *vma = vma_find_intersection(mgr, start, end);
        if (!vma)
            break;

        if (vma->vm_start < start) {
            if (vma_split(mgr, vma, start) != 0)
                return (uint64_t)-ENOMEM;
            continue;
        }

        if (vma->vm_end > end) {
            if (vma_split(mgr, vma, end) != 0)
                return (uint64_t)-ENOMEM;
        }

        uint64_t unmap_start = vma->vm_start;
        uint64_t unmap_len = vma->vm_end - vma->vm_start;

        vma_remove(mgr, vma);
        vma_free(vma);
        unmap_page_range(pgdir, unmap_start, unmap_len);
    }

    return 0;
}

uint64_t sys_munmap(uint64_t addr, uint64_t size) {
    if (addr & (DEFAULT_PAGE_SIZE - 1)) {
        return (uint64_t)-EINVAL;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    uint64_t ret = do_munmap(addr, size);
    spin_unlock(&mgr->lock);
    return ret;
}

uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
    if (addr & (DEFAULT_PAGE_SIZE - 1)) {
        return (uint64_t)-EINVAL;
    }

    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (len == 0) {
        return (uint64_t)-EINVAL;
    }

    if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return (uint64_t)-EINVAL;
    }

    if (check_user_overflow(addr, len)) {
        return -EFAULT;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    uint64_t end = addr + len;

    spin_lock(&mgr->lock);

    // mprotect requires every page in range to be mapped by VMAs.
    uint64_t cursor = addr;
    while (cursor < end) {
        vma_t *vma = vma_find(mgr, cursor);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        if (vma->vm_end <= cursor) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        cursor = vma->vm_end < end ? vma->vm_end : end;
    }

    // Split VMAs at range boundaries so we can update permissions exactly.
    cursor = addr;
    while (cursor < end) {
        vma_t *vma = vma_find(mgr, cursor);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }

        if (vma->vm_start < cursor) {
            if (vma_split(mgr, vma, cursor) != 0) {
                spin_unlock(&mgr->lock);
                return (uint64_t)-ENOMEM;
            }
            vma = vma_find(mgr, cursor);
            if (!vma) {
                spin_unlock(&mgr->lock);
                return (uint64_t)-ENOMEM;
            }
        }

        uint64_t seg_end = vma->vm_end < end ? vma->vm_end : end;
        if (seg_end < vma->vm_end) {
            if (vma_split(mgr, vma, seg_end) != 0) {
                spin_unlock(&mgr->lock);
                return (uint64_t)-ENOMEM;
            }
        }

        vma->vm_flags &= ~(VMA_READ | VMA_WRITE | VMA_EXEC);
        if (prot & PROT_READ)
            vma->vm_flags |= VMA_READ;
        if (prot & PROT_WRITE)
            vma->vm_flags |= VMA_WRITE;
        if (prot & PROT_EXEC)
            vma->vm_flags |= VMA_EXEC;

        cursor = seg_end;
    }

    spin_unlock(&mgr->lock);

    uint64_t pt_flags = PT_FLAG_U;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_change_attribute_range(get_current_page_dir(true), addr, len, pt_flags);

    return 0;
}

static uint64_t vm_flags_to_prot(uint64_t vm_flags) {
    uint64_t prot = 0;
    if (vm_flags & VMA_READ)
        prot |= PROT_READ;
    if (vm_flags & VMA_WRITE)
        prot |= PROT_WRITE;
    if (vm_flags & VMA_EXEC)
        prot |= PROT_EXEC;
    return prot;
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

static bool ranges_overlap(uint64_t a_start, uint64_t a_end, uint64_t b_start,
                           uint64_t b_end) {
    return a_start < b_end && b_start < a_end;
}

static vma_t *mremap_dup_vma(vma_t *src, uint64_t new_start,
                             uint64_t new_size) {
    vma_t *dst = vma_alloc();
    if (!dst)
        return NULL;

    dst->vm_start = new_start;
    dst->vm_end = new_start + new_size;
    dst->vm_flags = src->vm_flags;
    dst->vm_type = src->vm_type;
    dst->node = src->node;
    dst->shm = src->shm;
    dst->shm_id = src->shm_id;
    dst->vm_offset = src->vm_offset;

    if (dst->node)
        dst->node->refcount++;

    if (src->vm_name) {
        dst->vm_name = strdup(src->vm_name);
        if (!dst->vm_name) {
            vma_free(dst);
            return NULL;
        }
    }

    return dst;
}

static uint64_t mremap_map_new_region(vma_t *new_vma, uint64_t addr,
                                      uint64_t size) {
    if (new_vma->vm_type == VMA_TYPE_FILE) {
        fd_t fd = {
            .node = new_vma->node,
            .flags = 0,
            .offset = new_vma->vm_offset,
            .close_on_exec = false,
        };
        uint64_t map_flags =
            (new_vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE;
        return (uint64_t)vfs_map(&fd, addr, size,
                                 vm_flags_to_prot(new_vma->vm_flags), map_flags,
                                 new_vma->vm_offset);
    }

    if (new_vma->vm_type == VMA_TYPE_ANON) {
        map_page_range(get_current_page_dir(true), addr, (uint64_t)-1, size,
                       vm_flags_to_pt_flags(new_vma->vm_flags));
        return addr;
    }

    return (uint64_t)-EINVAL;
}

static uint64_t mremap_shrink(vma_manager_t *mgr, vma_t *vma, uint64_t old_addr,
                              uint64_t old_size, uint64_t new_size) {
    uint64_t unmap_start = old_addr + new_size;
    uint64_t unmap_size = old_size - new_size;

    unmap_page_range(get_current_page_dir(true), unmap_start, unmap_size);
    vma->vm_end = unmap_start;
    mgr->vm_used -= unmap_size;

    return old_addr;
}

static uint64_t mremap_expand_inplace(vma_manager_t *mgr, vma_t *vma,
                                      uint64_t old_addr, uint64_t old_size,
                                      uint64_t new_size) {
    uint64_t old_end = old_addr + old_size;
    uint64_t new_end = old_addr + new_size;
    uint64_t expand_size = new_size - old_size;

    if (vma_find_intersection(mgr, old_end, new_end))
        return (uint64_t)-ENOMEM;

    if (vma->vm_type == VMA_TYPE_FILE) {
        fd_t fd = {
            .node = vma->node,
            .flags = 0,
            .offset = vma->vm_offset + old_size,
            .close_on_exec = false,
        };
        uint64_t map_flags =
            (vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE;
        uint64_t ret = (uint64_t)vfs_map(&fd, old_end, expand_size,
                                         vm_flags_to_prot(vma->vm_flags),
                                         map_flags, vma->vm_offset + old_size);
        if ((int64_t)ret < 0)
            return ret;
    } else if (vma->vm_type == VMA_TYPE_ANON) {
        map_page_range(get_current_page_dir(true), old_end, (uint64_t)-1,
                       expand_size, vm_flags_to_pt_flags(vma->vm_flags));
    } else {
        return (uint64_t)-EINVAL;
    }

    vma->vm_end = new_end;
    mgr->vm_used += expand_size;
    return old_addr;
}

static uint64_t mremap_move(vma_manager_t *mgr, vma_t *old_vma,
                            uint64_t old_addr, uint64_t old_size,
                            uint64_t new_size, uint64_t flags,
                            uint64_t new_addr) {
    uint64_t old_end = old_addr + old_size;
    uint64_t target = new_addr;

    if (flags & MREMAP_FIXED) {
        if (target < USER_MMAP_START || target > USER_MMAP_END - new_size)
            return (uint64_t)-ENOMEM;
        if (ranges_overlap(old_addr, old_end, target, target + new_size))
            return (uint64_t)-EINVAL;

        uint64_t unmap_ret = do_munmap(target, new_size);
        if ((int64_t)unmap_ret < 0)
            return unmap_ret;
    } else {
        target = find_unmapped_area(mgr, 0, new_size);
        if (target > (uint64_t)-4095UL)
            return target;
    }

    vma_t *new_vma = mremap_dup_vma(old_vma, target, new_size);
    if (!new_vma)
        return (uint64_t)-ENOMEM;

    if (vma_insert(mgr, new_vma) != 0) {
        vma_free(new_vma);
        return (uint64_t)-ENOMEM;
    }

    uint64_t map_ret = mremap_map_new_region(new_vma, target, new_size);
    if ((int64_t)map_ret < 0) {
        unmap_page_range(get_current_page_dir(true), target, new_size);
        vma_remove(mgr, new_vma);
        vma_free(new_vma);
        return map_ret;
    }

    if (old_vma->vm_type == VMA_ANON) {
        uint64_t copy_len = old_size < new_size ? old_size : new_size;
        if (copy_len > 0 && (old_vma->vm_flags & VMA_READ)) {
            uint64_t final_pt_flags = vm_flags_to_pt_flags(new_vma->vm_flags);
            bool need_temp_write = (new_vma->vm_flags & VMA_WRITE) == 0;

            if (need_temp_write) {
                map_change_attribute_range(get_current_page_dir(true), target,
                                           copy_len,
                                           final_pt_flags | PT_FLAG_W);
            }

            memmove((void *)target, (void *)old_addr, copy_len);

            if (need_temp_write) {
                map_change_attribute_range(get_current_page_dir(true), target,
                                           copy_len, final_pt_flags);
            }
        }
    }

    if (!(flags & MREMAP_DONTUNMAP)) {
        uint64_t unmap_old_ret = do_munmap(old_addr, old_size);
        if ((int64_t)unmap_old_ret < 0)
            return unmap_old_ret;
    }

    return target;
}

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr) {
    uint64_t supported_flags = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    uint64_t old_addr_aligned = PADDING_DOWN(old_addr, DEFAULT_PAGE_SIZE);
    uint64_t new_addr_aligned = PADDING_DOWN(new_addr, DEFAULT_PAGE_SIZE);
    uint64_t old_size_aligned = PADDING_UP(old_size, DEFAULT_PAGE_SIZE);
    uint64_t new_size_aligned = PADDING_UP(new_size, DEFAULT_PAGE_SIZE);

    if (flags & ~supported_flags)
        return (uint64_t)-EINVAL;
    if (old_size == 0 || new_size == 0)
        return (uint64_t)-EINVAL;
    if (new_size_aligned > USER_MMAP_END - USER_MMAP_START)
        return (uint64_t)-ENOMEM;
    if (old_addr != old_addr_aligned)
        return (uint64_t)-EINVAL;
    if (check_user_overflow(old_addr_aligned, old_size_aligned))
        return (uint64_t)-EFAULT;
    if (check_user_overflow(old_addr_aligned, new_size_aligned))
        return (uint64_t)-EFAULT;
    if ((flags & MREMAP_FIXED) &&
        (!(flags & MREMAP_MAYMOVE) || new_addr != new_addr_aligned ||
         new_addr == 0))
        return (uint64_t)-EINVAL;
    if ((flags & MREMAP_FIXED) &&
        (new_addr_aligned < USER_MMAP_START ||
         new_addr_aligned > USER_MMAP_END - new_size_aligned))
        return (uint64_t)-ENOMEM;
    if ((flags & MREMAP_DONTUNMAP) && !(flags & MREMAP_MAYMOVE))
        return (uint64_t)-EINVAL;
    if ((flags & MREMAP_DONTUNMAP) && old_size_aligned != new_size_aligned)
        return (uint64_t)-EINVAL;

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    spin_lock(&mgr->lock);

    vma_t *vma = vma_find(mgr, old_addr_aligned);
    if (!vma || old_addr_aligned + old_size_aligned > vma->vm_end) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EFAULT;
    }

    if (vma->vm_type == VMA_TYPE_SHM) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EINVAL;
    }

    if (old_addr_aligned > vma->vm_start) {
        if (vma_split(mgr, vma, old_addr_aligned) != 0) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        vma = vma_find(mgr, old_addr_aligned);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-EFAULT;
        }
    }

    uint64_t old_end = old_addr_aligned + old_size_aligned;
    if (old_end < vma->vm_end) {
        if (vma_split(mgr, vma, old_end) != 0) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        vma = vma_find(mgr, old_addr_aligned);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-EFAULT;
        }
    }

    if ((flags & MREMAP_DONTUNMAP) &&
        (vma->vm_type != VMA_TYPE_ANON || (vma->vm_flags & VMA_SHARED))) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EINVAL;
    }

    uint64_t ret;
    if (new_size_aligned == old_size_aligned && !(flags & MREMAP_FIXED) &&
        !(flags & MREMAP_DONTUNMAP)) {
        ret = old_addr_aligned;
    } else if (!(flags & MREMAP_FIXED) && new_size_aligned < old_size_aligned &&
               !(flags & MREMAP_DONTUNMAP)) {
        ret = mremap_shrink(mgr, vma, old_addr_aligned, old_size_aligned,
                            new_size_aligned);
    } else if (!(flags & MREMAP_FIXED) && new_size_aligned > old_size_aligned &&
               !(flags & MREMAP_DONTUNMAP)) {
        ret = mremap_expand_inplace(mgr, vma, old_addr_aligned,
                                    old_size_aligned, new_size_aligned);
        if ((int64_t)ret == -ENOMEM) {
            if (flags & MREMAP_MAYMOVE) {
                ret = mremap_move(mgr, vma, old_addr_aligned, old_size_aligned,
                                  new_size_aligned, flags, new_addr_aligned);
            }
        }
    } else {
        if (!(flags & MREMAP_MAYMOVE)) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        ret = mremap_move(mgr, vma, old_addr_aligned, old_size_aligned,
                          new_size_aligned, flags, new_addr_aligned);
    }

    spin_unlock(&mgr->lock);
    return ret;
}

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset) {
    uint64_t final_pt_flags = PT_FLAG_U;

    if (prot & PROT_READ)
        final_pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        final_pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        final_pt_flags |= PT_FLAG_X;

    uint64_t map_addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t map_len =
        (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t load_pt_flags = final_pt_flags | PT_FLAG_W;

    map_page_range(get_current_page_dir(true), map_addr, (uint64_t)-1, map_len,
                   load_pt_flags);

    uint64_t origin_offset = file->offset;
    file->offset = offset;
    ssize_t ret = vfs_read_fd(file, (void *)addr, offset, len);
    if (ret < 0) {
        file->offset = origin_offset;
        unmap_page_range(get_current_page_dir(true), map_addr, map_len);
        printk("Failed read file for mmap\n");
        return (void *)ret;
    }
    file->offset = origin_offset;

    if (load_pt_flags != final_pt_flags) {
        map_change_attribute_range(get_current_page_dir(true), map_addr,
                                   map_len, final_pt_flags);
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

    uint64_t start_page_addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t end_page_addr = (addr + size - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t num_pages =
        ((end_page_addr - start_page_addr) / DEFAULT_PAGE_SIZE) + 1;

    if (check_user_overflow(vec, num_pages)) {
        return -EFAULT;
    }

    uint64_t *page_dir = get_current_page_dir(true);
    uint64_t current_addr = start_page_addr;

    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t phys_addr = translate_address(page_dir, current_addr);

        uint8_t resident = (phys_addr != 0) ? 1 : 0;

        if (copy_to_user((void *)(vec + i), &resident, sizeof(uint8_t)))
            return -EFAULT;

        current_addr += DEFAULT_PAGE_SIZE;
    }

    return 0;
}
