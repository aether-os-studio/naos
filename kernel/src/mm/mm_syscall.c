#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

#define NUMA_NODE_COUNT 1

static bool mempolicy_mode_valid(int mode) {
    return mode >= MPOL_DEFAULT && mode <= MPOL_PREFERRED_MANY;
}

static uint64_t mempolicy_copy_nodemask_to_user(unsigned long *nmask,
                                                uint64_t maxnode) {
    if (!nmask)
        return 0;
    if (maxnode == 0)
        return (uint64_t)-EINVAL;

    uint64_t bits_per_long = sizeof(unsigned long) * 8;
    uint64_t words = (maxnode + bits_per_long - 1) / bits_per_long;

    for (uint64_t i = 0; i < words; i++) {
        unsigned long value = 0;
        if (i == 0)
            value = 1UL;
        if (copy_to_user(nmask + i, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }

    return 0;
}

static uint64_t do_munmap_locked(uint64_t addr, uint64_t size);

static inline uint64_t *mm_pgdir(task_mm_info_t *mm) {
    return mm ? (uint64_t *)phys_to_virt(mm->page_table_addr) : NULL;
}

static void mmap_put_fd_ref(fd_t *fd_ref) {
    if (!fd_ref)
        return;

    vfs_close(fd_ref->node);
    free(fd_ref);
}

static bool rlimit_is_infinite(size_t value) { return value == (size_t)-1; }

static bool user_range_valid(uint64_t addr, uint64_t len) {
    if (len == 0)
        return false;
    if (check_user_overflow(addr, len))
        return false;
    return true;
}

static bool user_mmap_range_valid(uint64_t addr, uint64_t len) {
    if (!user_range_valid(addr, len))
        return false;
    if (addr < USER_MMAP_START)
        return false;
    return true;
}

static uint64_t prot_to_vma_access_flags(uint64_t prot) {
    uint64_t vm_flags = 0;

    if (prot & PROT_READ)
        vm_flags |= VMA_READ;
    if (prot & PROT_WRITE)
        vm_flags |= VMA_WRITE;
    if (prot & PROT_EXEC)
        vm_flags |= VMA_EXEC;

    return vm_flags;
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

static bool ranges_overlap(uint64_t lhs_start, uint64_t lhs_end,
                           uint64_t rhs_start, uint64_t rhs_end) {
    return lhs_start < rhs_end && rhs_start < lhs_end;
}

static int mmap_check_flags_linux(uint64_t flags, uint64_t map_type) {
    const uint64_t supported_flags =
        MAP_TYPE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_GROWSDOWN |
        MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED | MAP_POPULATE |
        MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE;

    uint64_t unknown_flags = flags & ~supported_flags;
    if (unknown_flags && map_type == MAP_SHARED_VALIDATE)
        return -EOPNOTSUPP;

    if ((flags & MAP_SYNC) && map_type != MAP_SHARED_VALIDATE)
        return -EINVAL;

    return 0;
}

static int mmap_check_file_access(fd_t *file, uint64_t prot,
                                  uint64_t map_type) {
    uint64_t accmode = file->flags & O_ACCMODE_FLAGS;

    if ((prot & PROT_READ) && accmode == O_WRONLY)
        return -EACCES;

    if (prot & PROT_WRITE) {
        if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE) {
            if (accmode != O_RDWR)
                return -EACCES;
        } else if (accmode == O_WRONLY) {
            return -EACCES;
        }
    }

    return 0;
}

static int check_address_space_limit(vma_manager_t *mgr, uint64_t grow) {
    size_t limit = current_task->rlim[RLIMIT_AS].rlim_cur;

    if (rlimit_is_infinite(limit))
        return 0;
    if (mgr->vm_used > limit)
        return -ENOMEM;
    if (grow > limit - mgr->vm_used)
        return -ENOMEM;

    return 0;
}

static int check_data_limit(task_mm_info_t *mm, uint64_t new_brk) {
    size_t limit = current_task->rlim[RLIMIT_DATA].rlim_cur;

    if (rlimit_is_infinite(limit))
        return 0;
    if (new_brk < mm->brk_start)
        return -ENOMEM;
    if (new_brk - mm->brk_start > limit)
        return -ENOMEM;

    return 0;
}

static uint64_t find_unmapped_area_in_window(vma_manager_t *mgr,
                                             uint64_t window_start,
                                             uint64_t window_end,
                                             uint64_t len) {
    window_start = PADDING_UP(window_start, DEFAULT_PAGE_SIZE);
    window_end = PADDING_DOWN(window_end, DEFAULT_PAGE_SIZE);

    if (window_start >= window_end)
        return (uint64_t)-ENOMEM;
    if (len == 0 || len > window_end - window_start)
        return (uint64_t)-ENOMEM;

    uint64_t cursor = window_start;
    uint64_t best = (uint64_t)-ENOMEM;
    rb_node_t *node = rb_first(&mgr->vma_tree);

    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        node = rb_next(node);

        if (vma->vm_end <= cursor)
            continue;
        if (vma->vm_start >= window_end)
            break;

        if (vma->vm_start > cursor) {
            uint64_t gap_end = vma->vm_start;
            if (gap_end > window_end)
                gap_end = window_end;
            if (gap_end > cursor && gap_end - cursor >= len)
                best = gap_end - len;
        }

        cursor = PADDING_UP(vma->vm_end, DEFAULT_PAGE_SIZE);
        if (cursor < vma->vm_end || cursor >= window_end)
            return best;
    }

    if (cursor < window_end && window_end - cursor >= len)
        best = window_end - len;

    return best;
}

uint64_t find_unmapped_area(vma_manager_t *mgr, uint64_t hint, uint64_t len) {
    if (len == 0)
        return (uint64_t)-ENOMEM;

    len = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    if (len == 0)
        return (uint64_t)-ENOMEM;
    if (USER_MMAP_END <= USER_MMAP_START)
        return (uint64_t)-ENOMEM;
    if (len > USER_MMAP_END - USER_MMAP_START)
        return (uint64_t)-ENOMEM;

    if (hint) {
        hint = PADDING_DOWN(hint, DEFAULT_PAGE_SIZE);
        if (hint >= USER_MMAP_START && hint <= USER_MMAP_END - len) {
            if (!vma_find_intersection(mgr, hint, hint + len))
                return hint;

            uint64_t downward = find_unmapped_area_in_window(
                mgr, USER_MMAP_START, hint + len, len);
            if ((int64_t)downward >= 0)
                return downward;

            if (hint + len < USER_MMAP_END) {
                uint64_t wrapped = find_unmapped_area_in_window(
                    mgr, hint + len, USER_MMAP_END, len);
                if ((int64_t)wrapped >= 0)
                    return wrapped;
            }
        }
    }

    return find_unmapped_area_in_window(mgr, USER_MMAP_START, USER_MMAP_END,
                                        len);
}

static bool range_fully_covered_locked(vma_manager_t *mgr, uint64_t start,
                                       uint64_t end) {
    uint64_t cursor = start;

    while (cursor < end) {
        vma_t *vma = vma_find(mgr, cursor);
        if (!vma || vma->vm_end <= cursor)
            return false;
        cursor = vma->vm_end < end ? vma->vm_end : end;
    }

    return true;
}

static int split_vma_boundaries_locked(vma_manager_t *mgr, uint64_t start,
                                       uint64_t end) {
    if (start >= end)
        return 0;

    while (true) {
        vma_t *vma = vma_find(mgr, start);
        if (!vma)
            break;
        if (vma->vm_start < start && start < vma->vm_end) {
            if (vma_split(mgr, vma, start) != 0)
                return -ENOMEM;
            continue;
        }
        break;
    }

    while (true) {
        vma_t *vma = vma_find_intersection(mgr, start, end);
        if (!vma)
            break;
        if (vma->vm_start < end && end < vma->vm_end) {
            if (vma_split(mgr, vma, end) != 0)
                return -ENOMEM;
            continue;
        }
        break;
    }

    return 0;
}

static vma_t *alloc_mapping_vma(uint64_t start, uint64_t len, uint64_t prot,
                                uint64_t map_type, bool anonymous,
                                vfs_node_t node, uint64_t offset) {
    vma_t *vma = vma_alloc();
    if (!vma)
        return NULL;

    vma->vm_start = start;
    vma->vm_end = start + len;
    vma->vm_flags = prot_to_vma_access_flags(prot);
    if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
        vma->vm_flags |= VMA_SHARED;

    if (anonymous) {
        vma->vm_type = VMA_TYPE_ANON;
        vma->vm_flags |= VMA_ANON;
        return vma;
    }

    vma->vm_type = VMA_TYPE_FILE;
    vma->node = node;
    vma->vm_offset = offset;
    if (node)
        node->refcount++;

    if (node && ((node->type & file_stream) || (node->type & file_block)))
        vma->vm_flags |= VMA_DEVICE;

    if (node) {
        char *fullpath = vfs_get_fullpath(node);
        if (fullpath) {
            vma->vm_name = strdup(fullpath);
            free(fullpath);
        }
    }

    return vma;
}

static uint64_t map_file_vma(fd_t *file, uint64_t offset, uint64_t addr,
                             uint64_t len, uint64_t prot, uint64_t flags) {
    uint64_t ret = (uint64_t)vfs_map(file, addr, len, prot, flags, offset);
    if ((int64_t)ret < 0)
        return ret;
    return addr;
}

static uint64_t populate_anon_vma(uint64_t vm_flags, uint64_t addr,
                                  uint64_t len, bool writable_override) {
    uint64_t pt_flags = vm_flags_to_pt_flags(vm_flags);
    task_mm_info_t *mm = current_task->mm;

    if (writable_override)
        pt_flags |= PT_FLAG_W;

    spin_lock(&mm->lock);
    map_page_range(mm_pgdir(mm), addr, (uint64_t)-1, len, pt_flags);
    spin_unlock(&mm->lock);
    return addr;
}

static bool should_eager_map_file(vma_t *vma, uint64_t flags) {
    if (!vma)
        return false;
    if (vma->vm_flags & VMA_DEVICE)
        return true;
    if (flags & (MAP_POPULATE | MAP_LOCKED))
        return true;
    if (vma->vm_flags & VMA_SHARED)
        return true;
    if (vma->vm_flags & VMA_WRITE)
        return true;
    if (vma->vm_flags & VMA_DEVICE)
        return true;
    return false;
}

static bool should_eager_map_anon(uint64_t flags) {
    return (flags & (MAP_POPULATE | MAP_LOCKED)) != 0;
}

uint64_t sys_brk(uint64_t brk) {
    task_mm_info_t *mm = current_task->mm;
    vma_manager_t *mgr = &mm->task_vma_mgr;
    uint64_t old_brk = mm->brk_current;

    if (brk == 0)
        return old_brk;
    if (brk < mm->brk_start || brk > mm->brk_end)
        return old_brk;

    uint64_t old_map_end = PADDING_UP(old_brk, DEFAULT_PAGE_SIZE);
    uint64_t new_map_end = PADDING_UP(brk, DEFAULT_PAGE_SIZE);

    spin_lock(&mgr->lock);

    if (new_map_end > old_map_end) {
        uint64_t grow = new_map_end - old_map_end;
        if (check_data_limit(mm, brk) != 0 ||
            check_address_space_limit(mgr, grow) != 0)
            goto fail;
        if (!user_range_valid(old_map_end, grow))
            goto fail;
        if (vma_find_intersection(mgr, old_map_end, new_map_end))
            goto fail;

        vma_t *heap_vma = NULL;
        if (old_map_end > mm->brk_start)
            heap_vma = vma_find(mgr, old_map_end - 1);

        bool extend_tail =
            heap_vma && heap_vma->vm_end == old_map_end &&
            heap_vma->vm_type == VMA_TYPE_ANON && !heap_vma->node &&
            !heap_vma->shm &&
            !(heap_vma->vm_flags & (VMA_SHARED | VMA_SHM | VMA_DEVICE)) &&
            (heap_vma->vm_flags & (VMA_READ | VMA_WRITE | VMA_EXEC)) ==
                (VMA_READ | VMA_WRITE);

        if (extend_tail) {
            heap_vma->vm_end = new_map_end;
            mgr->vm_used += grow;
        } else if (grow > 0) {
            vma_t *new_vma = vma_alloc();
            if (!new_vma)
                goto fail;

            new_vma->vm_start = old_map_end;
            new_vma->vm_end = new_map_end;
            new_vma->vm_flags = VMA_READ | VMA_WRITE | VMA_ANON;
            new_vma->vm_type = VMA_TYPE_ANON;
            new_vma->vm_name = strdup("[heap]");

            if (vma_insert(mgr, new_vma) != 0) {
                vma_free(new_vma);
                goto fail;
            }
        }
    } else if (new_map_end < old_map_end) {
        uint64_t ret = do_munmap_locked(new_map_end, old_map_end - new_map_end);
        if ((int64_t)ret < 0)
            goto fail;
    }

    mm->brk_current = brk;
    spin_unlock(&mgr->lock);
    return mm->brk_current;

fail:
    spin_unlock(&mgr->lock);
    return old_brk;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                  uint64_t fd, uint64_t offset) {
    const uint64_t page_mask = DEFAULT_PAGE_SIZE - 1;
    uint64_t map_type = flags & MAP_TYPE;
    uint64_t aligned_len = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    bool anonymous = (flags & MAP_ANONYMOUS) != 0;
    bool fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    bool no_replace = (flags & MAP_FIXED_NOREPLACE) != 0;

    if (len == 0 || aligned_len == 0 || aligned_len < len)
        return (uint64_t)-EINVAL;
    if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
        return (uint64_t)-EINVAL;
    if (map_type != MAP_PRIVATE && map_type != MAP_SHARED &&
        map_type != MAP_SHARED_VALIDATE)
        return (uint64_t)-EINVAL;
    int check_ret = mmap_check_flags_linux(flags, map_type);
    if (check_ret != 0)
        return (uint64_t)check_ret;
    if (offset & page_mask)
        return (uint64_t)-EINVAL;
    if (anonymous && offset != 0)
        return (uint64_t)-EINVAL;
    if ((flags & MAP_SYNC) && anonymous)
        return (uint64_t)-EINVAL;
    if (aligned_len > USER_MMAP_END - USER_MMAP_START)
        return (uint64_t)-ENOMEM;

    task_mm_info_t *mm_info = current_task->mm;
    fd_t *map_fd_ref = NULL;
    vfs_node_t map_node = NULL;
    int access_ret = 0;
    if (!anonymous) {
        if (fd >= MAX_FD_NUM)
            return (uint64_t)-EBADF;

        int map_fd_err = 0;
        with_fd_info_lock(current_task->fd_info, {
            fd_t *entry = current_task->fd_info->fds[fd];
            if (!entry || !entry->node) {
                map_fd_err = -EBADF;
                break;
            }

            map_fd_ref = vfs_dup(entry);
            if (!map_fd_ref) {
                map_fd_err = -ENOMEM;
                break;
            }
        });
        if (map_fd_err < 0)
            return (uint64_t)map_fd_err;

        map_node = map_fd_ref->node;
        if (map_node->type & file_dir)
            goto out_map_fd_eisdir;
        if (flags & MAP_SYNC)
            goto out_map_fd_eopnotsupp;

        access_ret = mmap_check_file_access(map_fd_ref, prot, map_type);
        if (access_ret < 0)
            goto out_map_fd_error;
    }

    vma_manager_t *mgr = &mm_info->task_vma_mgr;
    uint64_t start_addr = 0;
    uint64_t eager_vm_flags = 0;
    uint64_t eager_vm_offset = 0;
    bool eager_map_anon = false;
    bool eager_map_file_now = false;

    spin_lock(&mgr->lock);

    if (fixed) {
        if (addr & page_mask) {
            spin_unlock(&mgr->lock);
            mmap_put_fd_ref(map_fd_ref);
            return (uint64_t)-EINVAL;
        }
        if (!user_mmap_range_valid(addr, aligned_len)) {
            spin_unlock(&mgr->lock);
            mmap_put_fd_ref(map_fd_ref);
            return (uint64_t)-ENOMEM;
        }

        start_addr = addr;
        if (vma_find_intersection(mgr, start_addr, start_addr + aligned_len)) {
            if (no_replace) {
                spin_unlock(&mgr->lock);
                mmap_put_fd_ref(map_fd_ref);
                return (uint64_t)-EEXIST;
            }

            uint64_t ret = do_munmap_locked(start_addr, aligned_len);
            if ((int64_t)ret < 0) {
                spin_unlock(&mgr->lock);
                mmap_put_fd_ref(map_fd_ref);
                return ret;
            }
        }
    } else {
        uint64_t hint = 0;
        if (addr >= USER_MMAP_START && addr < USER_MMAP_END)
            hint = PADDING_DOWN(addr, DEFAULT_PAGE_SIZE);

        start_addr = find_unmapped_area(mgr, hint, aligned_len);
        if ((int64_t)start_addr < 0) {
            spin_unlock(&mgr->lock);
            mmap_put_fd_ref(map_fd_ref);
            return start_addr;
        }
    }

    if (check_address_space_limit(mgr, aligned_len) != 0) {
        spin_unlock(&mgr->lock);
        mmap_put_fd_ref(map_fd_ref);
        return (uint64_t)-ENOMEM;
    }

    vma_t *vma = alloc_mapping_vma(start_addr, aligned_len, prot, map_type,
                                   anonymous, map_node, offset);
    if (!vma) {
        spin_unlock(&mgr->lock);
        goto out_map_fd_nomem;
    }

    if (vma_insert(mgr, vma) != 0) {
        spin_unlock(&mgr->lock);
        vma_free(vma);
        goto out_map_fd_nomem;
    }

    eager_vm_flags = vma->vm_flags;
    eager_vm_offset = (uint64_t)vma->vm_offset;
    eager_map_anon = anonymous && should_eager_map_anon(flags);
    eager_map_file_now = !anonymous && should_eager_map_file(vma, flags);

    spin_unlock(&mgr->lock);

    uint64_t ret = start_addr;
    if (eager_map_anon) {
        ret = populate_anon_vma(eager_vm_flags, start_addr, aligned_len, false);
    } else if (eager_map_file_now) {
        ret = map_file_vma(map_fd_ref, eager_vm_offset, start_addr, aligned_len,
                           prot, flags);
    }

    mmap_put_fd_ref(map_fd_ref);
    map_fd_ref = NULL;

    if ((int64_t)ret < 0) {
        spin_lock(&mm_info->lock);
        unmap_page_range(mm_pgdir(mm_info), start_addr, aligned_len);
        spin_unlock(&mm_info->lock);
        spin_lock(&mgr->lock);
        vma_remove(mgr, vma);
        spin_unlock(&mgr->lock);
        vma_free(vma);
        return ret;
    }

    return start_addr;

out_map_fd_nomem:
    mmap_put_fd_ref(map_fd_ref);
    return (uint64_t)-ENOMEM;

out_map_fd_eisdir:
    mmap_put_fd_ref(map_fd_ref);
    return (uint64_t)-EISDIR;

out_map_fd_eopnotsupp:
    mmap_put_fd_ref(map_fd_ref);
    return (uint64_t)-EOPNOTSUPP;

out_map_fd_error:
    mmap_put_fd_ref(map_fd_ref);
    return (uint64_t)access_ret;
}

static uint64_t do_munmap_locked(uint64_t addr, uint64_t size) {
    addr = PADDING_DOWN(addr, DEFAULT_PAGE_SIZE);
    size = PADDING_UP(size, DEFAULT_PAGE_SIZE);

    if (size == 0)
        return (uint64_t)-EINVAL;
    if (!user_range_valid(addr, size))
        return (uint64_t)-EFAULT;

    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    task_mm_info_t *mm = current_task->mm;
    uint64_t end = addr + size;

    if (split_vma_boundaries_locked(mgr, addr, end) != 0)
        return (uint64_t)-ENOMEM;

    while (true) {
        vma_t *vma = vma_find_intersection(mgr, addr, end);
        if (!vma)
            break;
        if (vma->vm_start < addr || vma->vm_end > end)
            return (uint64_t)-ENOMEM;

        uint64_t unmap_start = vma->vm_start;
        uint64_t unmap_len = vma->vm_end - vma->vm_start;

        if (vma_remove(mgr, vma) != 0)
            return (uint64_t)-ENOMEM;
        vma_free(vma);
        spin_lock(&mm->lock);
        unmap_page_range(mm_pgdir(mm), unmap_start, unmap_len);
        spin_unlock(&mm->lock);
    }

    return 0;
}

uint64_t sys_munmap(uint64_t addr, uint64_t size) {
    if (addr & (DEFAULT_PAGE_SIZE - 1))
        return (uint64_t)-EINVAL;

    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    uint64_t ret = do_munmap_locked(addr, size);
    spin_unlock(&mgr->lock);
    return ret;
}

uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
    if (addr & (DEFAULT_PAGE_SIZE - 1))
        return (uint64_t)-EINVAL;
    if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
        return (uint64_t)-EINVAL;

    len = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    if (len == 0)
        return (uint64_t)-EINVAL;
    if (!user_range_valid(addr, len))
        return (uint64_t)-EFAULT;

    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    task_mm_info_t *mm = current_task->mm;
    uint64_t end = addr + len;

    spin_lock(&mgr->lock);

    if (!range_fully_covered_locked(mgr, addr, end)) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    if (split_vma_boundaries_locked(mgr, addr, end) != 0) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    uint64_t cursor = addr;
    while (cursor < end) {
        vma_t *vma = vma_find(mgr, cursor);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }

        vma->vm_flags &= ~(VMA_READ | VMA_WRITE | VMA_EXEC);
        vma->vm_flags |= prot_to_vma_access_flags(prot);
        cursor = vma->vm_end;
    }

    spin_lock(&mm->lock);
    map_change_attribute_range(
        mm_pgdir(mm), addr, len,
        vm_flags_to_pt_flags(prot_to_vma_access_flags(prot)));
    spin_unlock(&mm->lock);

    spin_unlock(&mgr->lock);
    return 0;
}

static vma_t *duplicate_vma(vma_t *src, uint64_t start, uint64_t size) {
    vma_t *dst = vma_alloc();
    if (!dst)
        return NULL;

    dst->vm_start = start;
    dst->vm_end = start + size;
    dst->vm_flags = src->vm_flags;
    dst->vm_type = src->vm_type;
    dst->node = src->node;
    dst->shm = src->shm;
    dst->shm_id = src->shm_id;
    dst->vm_offset = src->vm_offset;

    if (dst->node)
        dst->node->refcount++;
    if (src->vm_name)
        dst->vm_name = strdup(src->vm_name);

    return dst;
}

static uint64_t mremap_map_new_region(vma_t *new_vma, uint64_t addr,
                                      uint64_t size) {
    if (new_vma->vm_type == VMA_TYPE_ANON)
        return addr;

    if (new_vma->vm_type != VMA_TYPE_FILE)
        return (uint64_t)-EINVAL;

    fd_t fd = {
        .node = new_vma->node,
        .flags = 0,
        .offset = (uint64_t)new_vma->vm_offset,
        .close_on_exec = false,
    };

    uint64_t map_flags =
        (new_vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE;
    return map_file_vma(&fd, (uint64_t)new_vma->vm_offset, addr, size,
                        vm_flags_to_prot(new_vma->vm_flags), map_flags);
}

static uint64_t prepare_copy_target(vma_t *vma, uint64_t addr, uint64_t size) {
    if (size == 0)
        return 0;

    if (vma->vm_type == VMA_TYPE_ANON)
        return populate_anon_vma(vma->vm_flags, addr, size, true);

    uint64_t pt_flags = vm_flags_to_pt_flags(vma->vm_flags) | PT_FLAG_W;
    task_mm_info_t *mm = current_task->mm;
    spin_lock(&mm->lock);
    map_change_attribute_range(mm_pgdir(mm), addr, size, pt_flags);
    spin_unlock(&mm->lock);
    return 0;
}

static void restore_copy_target_permissions(vma_t *vma, uint64_t addr,
                                            uint64_t size) {
    if (size == 0)
        return;

    task_mm_info_t *mm = current_task->mm;
    spin_lock(&mm->lock);
    map_change_attribute_range(mm_pgdir(mm), addr, size,
                               vm_flags_to_pt_flags(vma->vm_flags));
    spin_unlock(&mm->lock);
}

static int copy_user_range_mapped(uint64_t dst, uint64_t src, uint64_t size) {
    if (size == 0)
        return 0;

    task_mm_info_t *mm = current_task->mm;
    uint64_t *pgdir = mm_pgdir(mm);
    uint64_t src_addr = src;
    uint64_t dst_addr = dst;
    uint64_t remain = size;

    spin_lock(&mm->lock);
    while (remain > 0) {
        uint64_t src_pa = translate_address(pgdir, src_addr);
        uint64_t dst_pa = translate_address(pgdir, dst_addr);
        if (!src_pa || !dst_pa) {
            spin_unlock(&mm->lock);
            return -EFAULT;
        }

        uint64_t src_chunk =
            DEFAULT_PAGE_SIZE - (src_addr & (DEFAULT_PAGE_SIZE - 1));
        uint64_t dst_chunk =
            DEFAULT_PAGE_SIZE - (dst_addr & (DEFAULT_PAGE_SIZE - 1));
        uint64_t chunk = MIN(remain, MIN(src_chunk, dst_chunk));

        memcpy((void *)phys_to_virt(dst_pa), (const void *)phys_to_virt(src_pa),
               chunk);

        src_addr += chunk;
        dst_addr += chunk;
        remain -= chunk;
    }

    spin_unlock(&mm->lock);

    return 0;
}

static bool mremap_should_copy_data(vma_t *vma) {
    if (vma->vm_type == VMA_TYPE_ANON)
        return true;
    if (vma->vm_type == VMA_TYPE_FILE && !(vma->vm_flags & VMA_SHARED) &&
        !(vma->vm_flags & VMA_DEVICE))
        return true;
    return false;
}

static uint64_t mremap_shrink_locked(vma_manager_t *mgr, vma_t *vma,
                                     uint64_t old_addr, uint64_t old_size,
                                     uint64_t new_size) {
    uint64_t shrink_start = old_addr + new_size;
    uint64_t shrink_size = old_size - new_size;

    if (shrink_size == 0)
        return old_addr;

    task_mm_info_t *mm = current_task->mm;
    spin_lock(&mm->lock);
    unmap_page_range(mm_pgdir(mm), shrink_start, shrink_size);
    spin_unlock(&mm->lock);
    vma->vm_end = shrink_start;
    mgr->vm_used -= shrink_size;
    return old_addr;
}

static uint64_t mremap_expand_inplace_locked(vma_manager_t *mgr, vma_t *vma,
                                             uint64_t old_addr,
                                             uint64_t old_size,
                                             uint64_t new_size) {
    uint64_t old_end = old_addr + old_size;
    uint64_t new_end = old_addr + new_size;
    uint64_t grow = new_size - old_size;

    if (grow == 0)
        return old_addr;
    if (!user_mmap_range_valid(old_addr, new_size))
        return (uint64_t)-ENOMEM;
    if (check_address_space_limit(mgr, grow) != 0)
        return (uint64_t)-ENOMEM;
    if (vma_find_intersection(mgr, old_end, new_end))
        return (uint64_t)-ENOMEM;

    if (vma->vm_type == VMA_TYPE_FILE &&
        ((vma->vm_flags & VMA_SHARED) || (vma->vm_flags & VMA_DEVICE))) {
        fd_t fd = {
            .node = vma->node,
            .flags = 0,
            .offset = (uint64_t)vma->vm_offset + old_size,
            .close_on_exec = false,
        };
        uint64_t map_flags =
            (vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE;
        uint64_t ret = (uint64_t)vfs_map(
            &fd, old_end, grow, vm_flags_to_prot(vma->vm_flags), map_flags,
            (uint64_t)vma->vm_offset + old_size);
        if ((int64_t)ret < 0)
            return ret;
    }

    vma->vm_end = new_end;
    mgr->vm_used += grow;
    return old_addr;
}

static uint64_t mremap_move_locked(vma_manager_t *mgr, vma_t *old_vma,
                                   uint64_t old_addr, uint64_t old_size,
                                   uint64_t new_size, uint64_t flags,
                                   uint64_t new_addr) {
    uint64_t target = new_addr;

    if (flags & MREMAP_FIXED) {
        if (!user_mmap_range_valid(target, new_size))
            return (uint64_t)-ENOMEM;
        if (ranges_overlap(old_addr, old_addr + old_size, target,
                           target + new_size))
            return (uint64_t)-EINVAL;

        uint64_t ret = do_munmap_locked(target, new_size);
        if ((int64_t)ret < 0)
            return ret;
    } else {
        target = find_unmapped_area(mgr, 0, new_size);
        if ((int64_t)target < 0)
            return target;
    }

    uint64_t extra_space =
        (flags & MREMAP_DONTUNMAP)
            ? new_size
            : (new_size > old_size ? new_size - old_size : 0);
    if (check_address_space_limit(mgr, extra_space) != 0)
        return (uint64_t)-ENOMEM;

    vma_t *new_vma = duplicate_vma(old_vma, target, new_size);
    if (!new_vma)
        return (uint64_t)-ENOMEM;

    if (vma_insert(mgr, new_vma) != 0) {
        vma_free(new_vma);
        return (uint64_t)-ENOMEM;
    }

    uint64_t map_ret = mremap_map_new_region(new_vma, target, new_size);
    if ((int64_t)map_ret < 0) {
        task_mm_info_t *mm = current_task->mm;
        spin_lock(&mm->lock);
        unmap_page_range(mm_pgdir(mm), target, new_size);
        spin_unlock(&mm->lock);
        vma_remove(mgr, new_vma);
        vma_free(new_vma);
        return map_ret;
    }

    if (mremap_should_copy_data(old_vma) && (old_vma->vm_flags & VMA_READ)) {
        uint64_t copy_len = old_size < new_size ? old_size : new_size;
        if (copy_len > 0) {
            prepare_copy_target(new_vma, target, copy_len);
            if (copy_user_range_mapped(target, old_addr, copy_len) != 0) {
                task_mm_info_t *mm = current_task->mm;
                spin_lock(&mm->lock);
                unmap_page_range(mm_pgdir(mm), target, new_size);
                spin_unlock(&mm->lock);
                vma_remove(mgr, new_vma);
                vma_free(new_vma);
                return (uint64_t)-EFAULT;
            }
            if (!(new_vma->vm_flags & VMA_WRITE))
                restore_copy_target_permissions(new_vma, target, copy_len);
        }
    }

    if (!(flags & MREMAP_DONTUNMAP)) {
        uint64_t ret = do_munmap_locked(old_addr, old_size);
        if ((int64_t)ret < 0)
            return ret;
    }

    return target;
}

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr) {
    const uint64_t supported_flags =
        MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;

    uint64_t old_addr_aligned = PADDING_DOWN(old_addr, DEFAULT_PAGE_SIZE);
    uint64_t new_addr_aligned = PADDING_DOWN(new_addr, DEFAULT_PAGE_SIZE);
    uint64_t old_size_aligned = PADDING_UP(old_size, DEFAULT_PAGE_SIZE);
    uint64_t new_size_aligned = PADDING_UP(new_size, DEFAULT_PAGE_SIZE);

    if (flags & ~supported_flags)
        return (uint64_t)-EINVAL;
    if (old_size == 0 || new_size == 0)
        return (uint64_t)-EINVAL;
    if (old_addr != old_addr_aligned)
        return (uint64_t)-EINVAL;
    if (!user_range_valid(old_addr_aligned, old_size_aligned) ||
        !user_range_valid(old_addr_aligned, new_size_aligned))
        return (uint64_t)-EFAULT;
    if (new_size_aligned > USER_MMAP_END - USER_MMAP_START)
        return (uint64_t)-ENOMEM;
    if ((flags & MREMAP_FIXED) && (!(flags & MREMAP_MAYMOVE) || new_addr == 0 ||
                                   new_addr != new_addr_aligned))
        return (uint64_t)-EINVAL;
    if ((flags & MREMAP_FIXED) &&
        !user_mmap_range_valid(new_addr_aligned, new_size_aligned))
        return (uint64_t)-ENOMEM;
    if ((flags & MREMAP_DONTUNMAP) && !(flags & MREMAP_MAYMOVE))
        return (uint64_t)-EINVAL;
    if ((flags & MREMAP_DONTUNMAP) && old_size_aligned != new_size_aligned)
        return (uint64_t)-EINVAL;

    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
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

    if (split_vma_boundaries_locked(mgr, old_addr_aligned,
                                    old_addr_aligned + old_size_aligned) != 0) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    vma = vma_find(mgr, old_addr_aligned);
    if (!vma || vma->vm_start != old_addr_aligned ||
        vma->vm_end != old_addr_aligned + old_size_aligned) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EFAULT;
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
        ret = mremap_shrink_locked(mgr, vma, old_addr_aligned, old_size_aligned,
                                   new_size_aligned);
    } else if (!(flags & MREMAP_FIXED) && new_size_aligned > old_size_aligned &&
               !(flags & MREMAP_DONTUNMAP)) {
        ret = mremap_expand_inplace_locked(mgr, vma, old_addr_aligned,
                                           old_size_aligned, new_size_aligned);
        if ((int64_t)ret == -ENOMEM && (flags & MREMAP_MAYMOVE)) {
            ret =
                mremap_move_locked(mgr, vma, old_addr_aligned, old_size_aligned,
                                   new_size_aligned, flags, new_addr_aligned);
        }
    } else {
        if (!(flags & MREMAP_MAYMOVE)) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-ENOMEM;
        }
        ret = mremap_move_locked(mgr, vma, old_addr_aligned, old_size_aligned,
                                 new_size_aligned, flags, new_addr_aligned);
    }

    spin_unlock(&mgr->lock);
    return ret;
}

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset) {
    (void)flags;

    uint64_t final_pt_flags = PT_FLAG_U;
    if (prot & PROT_READ)
        final_pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        final_pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        final_pt_flags |= PT_FLAG_X;

    uint64_t map_addr = PADDING_DOWN(addr, DEFAULT_PAGE_SIZE);
    uint64_t page_off = addr - map_addr;
    uint64_t map_len = PADDING_UP(len + page_off, DEFAULT_PAGE_SIZE);
    uint64_t load_pt_flags = final_pt_flags | PT_FLAG_W;
    task_mm_info_t *mm = current_task->mm;
    uint64_t *pgdir = mm_pgdir(mm);

    spin_lock(&mm->lock);
    map_page_range(pgdir, map_addr, (uint64_t)-1, map_len, load_pt_flags);
    spin_unlock(&mm->lock);

    uint64_t cursor = addr;
    uint64_t remaining = len;
    uint64_t file_off = offset;

    while (remaining > 0) {
        uint64_t page_va = PADDING_DOWN(cursor, DEFAULT_PAGE_SIZE);
        spin_lock(&mm->lock);
        uint64_t page_paddr = translate_address(pgdir, page_va);
        spin_unlock(&mm->lock);
        if (!page_paddr) {
            spin_lock(&mm->lock);
            unmap_page_range(pgdir, map_addr, map_len);
            spin_unlock(&mm->lock);
            return (void *)(uint64_t)-ENOMEM;
        }

        uint64_t in_page = cursor - page_va;
        uint64_t chunk = DEFAULT_PAGE_SIZE - in_page;
        if (chunk > remaining)
            chunk = remaining;

        uint64_t loaded = 0;
        while (loaded < chunk) {
            ssize_t ret =
                vfs_read(file->node,
                         (void *)(phys_to_virt(page_paddr) + in_page + loaded),
                         file_off + loaded, chunk - loaded);
            if (ret < 0) {
                spin_lock(&mm->lock);
                unmap_page_range(pgdir, map_addr, map_len);
                spin_unlock(&mm->lock);
                printk("Failed read file for mmap\n");
                return (void *)ret;
            }
            if (ret == 0)
                break;
            loaded += (uint64_t)ret;
        }

        cursor += loaded;
        file_off += loaded;
        remaining -= loaded;

        if (loaded < chunk)
            break;
    }

    if (load_pt_flags != final_pt_flags) {
        spin_lock(&mm->lock);
        map_change_attribute_range(pgdir, map_addr, map_len, final_pt_flags);
        spin_unlock(&mm->lock);
    }

    return (void *)addr;
}

uint64_t sys_msync(uint64_t addr, uint64_t size, uint64_t flags) {
    (void)flags;

    if (addr & (DEFAULT_PAGE_SIZE - 1))
        return (uint64_t)-EINVAL;
    if (size == 0)
        return 0;
    if (!user_range_valid(addr, size))
        return (uint64_t)-ENOMEM;

    uint64_t end = addr + size;
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;

    spin_lock(&mgr->lock);
    bool covered = range_fully_covered_locked(mgr, addr, end);
    spin_unlock(&mgr->lock);

    return covered ? 0 : (uint64_t)-ENOMEM;
}

uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec) {
    if (addr & (DEFAULT_PAGE_SIZE - 1))
        return (uint64_t)-EINVAL;
    if (size == 0)
        return 0;
    if (!user_range_valid(addr, size))
        return (uint64_t)-ENOMEM;

    uint64_t num_pages = (size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE;
    if (check_user_overflow(vec, num_pages))
        return (uint64_t)-EFAULT;

    uint64_t end = addr + size;
    uint64_t *page_dir = mm_pgdir(current_task->mm);
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;

    spin_lock(&mgr->lock);

    if (!range_fully_covered_locked(mgr, addr, end)) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    spin_unlock(&mgr->lock);

    for (uint64_t index = 0, cursor = addr; index < num_pages;
         index++, cursor += DEFAULT_PAGE_SIZE) {
        uint8_t value = translate_address(page_dir, cursor) ? 1 : 0;
        if (copy_to_user((void *)vec + index, &value, 1)) {
            return (uint64_t)-EFAULT;
        }
    }

    return 0;
}

uint64_t sys_mbind(uint64_t start, uint64_t len, int mode,
                   const unsigned long *nmask, uint64_t maxnode,
                   uint64_t flags) {
    (void)start;
    (void)len;
    (void)nmask;
    (void)maxnode;

    const uint64_t supported_flags = 0;
    if (!mempolicy_mode_valid(mode))
        return (uint64_t)-EINVAL;
    if (flags & ~supported_flags)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_set_mempolicy(int mode, const unsigned long *nmask,
                           uint64_t maxnode) {
    (void)nmask;
    (void)maxnode;

    if (!mempolicy_mode_valid(mode))
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_get_mempolicy(int *policy, unsigned long *nmask, uint64_t maxnode,
                           uint64_t addr, uint64_t flags) {
    (void)addr;

    const uint64_t supported_flags =
        MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;

    if (flags & ~supported_flags)
        return (uint64_t)-EINVAL;
    if ((flags & MPOL_F_MEMS_ALLOWED) && (flags & (MPOL_F_NODE | MPOL_F_ADDR)))
        return (uint64_t)-EINVAL;

    uint64_t ret = mempolicy_copy_nodemask_to_user(nmask, maxnode);
    if ((int64_t)ret < 0)
        return ret;

    if (policy) {
        int value = MPOL_DEFAULT;
        if (flags & MPOL_F_NODE)
            value = 0;
        else if (flags & MPOL_F_MEMS_ALLOWED)
            value = MPOL_DEFAULT;

        if (copy_to_user(policy, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }

    return 0;
}
