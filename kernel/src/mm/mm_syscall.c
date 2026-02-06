#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

uint64_t do_munmap(uint64_t addr, uint64_t size);

static uint64_t find_unmapped_area(vma_manager_t *mgr, uint64_t hint,
                                   uint64_t len) {
    vma_t *vma;

    // 参数校验
    if (len == 0 || len > USER_MMAP_END - USER_MMAP_START) {
        return (uint64_t)-ENOMEM;
    }

    // 尝试hint
    if (hint) {
        hint = PADDING_UP(hint, DEFAULT_PAGE_SIZE);
        if (hint >= USER_MMAP_START && hint <= USER_MMAP_END - len &&
            !vma_find_intersection(mgr, hint, hint + len)) {
            return hint;
        }
    }

    // 使用红黑树找到第一个VMA
    rb_node_t *node = rb_first(&mgr->vma_tree);

    if (!node) {
        // 没有VMA，整个空间可用
        return USER_MMAP_START + len <= USER_MMAP_END ? USER_MMAP_START
                                                      : (uint64_t)-ENOMEM;
    }

    vma = rb_entry(node, vma_t, vm_rb);

    // 检查第一个VMA之前的gap
    if (vma->vm_start >= USER_MMAP_START + len) {
        return USER_MMAP_START;
    }

    // 扫描VMA间的gaps
    while ((node = rb_next(node)) != NULL) {
        vma_t *next_vma = rb_entry(node, vma_t, vm_rb);
        uint64_t gap_start = vma->vm_end;
        uint64_t gap_end = next_vma->vm_start;

        if (gap_end >= gap_start + len) {
            return gap_start;
        }

        vma = next_vma;
    }

    // 检查最后一个VMA之后
    if (vma->vm_end <= USER_MMAP_END - len) {
        return vma->vm_end;
    }

    return (uint64_t)-ENOMEM;
}

uint64_t sys_brk(uint64_t brk) {
    brk = (brk + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);

    if (!brk) {
        return current_task->arch_context->mm->brk_start;
    }

    if (brk < current_task->arch_context->mm->brk_start) {
        return current_task->arch_context->mm->brk_current;
    }

    if (brk == current_task->arch_context->mm->brk_current) {
        return current_task->arch_context->mm->brk_current;
    }

    spin_lock(&current_task->arch_context->mm->task_vma_mgr.lock);

    if (brk > current_task->arch_context->mm->brk_current) {
        map_page_range(get_current_page_dir(true),
                       current_task->arch_context->mm->brk_current, 0,
                       brk - current_task->arch_context->mm->brk_current,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

        vma_t *vma = vma_alloc();
        if (!vma) {
            spin_unlock(&current_task->arch_context->mm->task_vma_mgr.lock);
            return (uint64_t)-ENOMEM;
        }

        vma->vm_start = current_task->arch_context->mm->brk_current;
        vma->vm_end = brk;
        vma->vm_flags = VMA_READ | VMA_WRITE | VMA_ANON;
        vma->vm_type = VMA_TYPE_ANON;
        vma->node = NULL;
        vma->vm_name = strdup("[heap]");
        if (!vma->vm_name) {
            vma_free(vma);
            spin_unlock(&current_task->arch_context->mm->task_vma_mgr.lock);
            return (uint64_t)-ENOMEM;
        }

        vma_t *region =
            vma_find_intersection(&current_task->arch_context->mm->task_vma_mgr,
                                  current_task->arch_context->mm->brk_start,
                                  current_task->arch_context->mm->brk_end);

        if (region) {
            vma_remove(&current_task->arch_context->mm->task_vma_mgr, region);
            vma_free(region);
        }

        if (vma_insert(&current_task->arch_context->mm->task_vma_mgr, vma)) {
            vma_free(vma);
            spin_unlock(&current_task->arch_context->mm->task_vma_mgr.lock);
            return (uint64_t)-ENOMEM;
        }

        current_task->arch_context->mm->brk_current = brk;
    } else {
        unmap_page_range(get_current_page_dir(true), brk,
                         current_task->arch_context->mm->brk_current - brk);

        vma_t *region =
            vma_find_intersection(&current_task->arch_context->mm->task_vma_mgr,
                                  current_task->arch_context->mm->brk_start,
                                  current_task->arch_context->mm->brk_end);

        if (region) {
            vma_remove(&current_task->arch_context->mm->task_vma_mgr, region);
            vma_free(region);
        }

        if (brk > current_task->arch_context->mm->brk_start) {
            vma_t *vma = vma_alloc();
            if (!vma) {
                current_task->arch_context->mm->brk_current = brk;
                return current_task->arch_context->mm->brk_current;
            }

            vma->vm_start = current_task->arch_context->mm->brk_start;
            vma->vm_end = brk;
            vma->vm_flags = VMA_READ | VMA_WRITE | VMA_ANON;
            vma->vm_type = VMA_TYPE_ANON;
            vma->node = NULL;
            vma->vm_name = strdup("[heap]");

            if (vma_insert(&current_task->arch_context->mm->task_vma_mgr,
                           vma) != 0) {
                vma_free(vma);
                // 继续执行，即使VMA插入失败
            }
        }

        current_task->arch_context->mm->brk_current = brk;
    }

    spin_unlock(&current_task->arch_context->mm->task_vma_mgr.lock);

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

    spin_lock(&mgr->lock);

    if (flags & MAP_FIXED_NOREPLACE)
        flags |= MAP_FIXED;

    uint64_t start_addr;
    if (flags & MAP_FIXED) {
        if (!addr) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-EINVAL;
        }

        start_addr = (uint64_t)addr;

        vma_t *region =
            vma_find_intersection(mgr, start_addr, start_addr + aligned_len);
        if (region) {
            if (flags & MAP_FIXED_NOREPLACE)
                return (uint64_t)-EEXIST;
            do_munmap(start_addr, aligned_len);
        }
    } else {
        start_addr = find_unmapped_area(mgr, addr, aligned_len);
        if (start_addr > (uint64_t)-4095UL)
            return start_addr;
    }

    if (!(flags & MAP_ANONYMOUS)) {
        if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd]) {
            spin_unlock(&mgr->lock);
            return (uint64_t)-EBADF;
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
    if (flags & MAP_SHARED)
        vma->vm_flags |= VMA_SHARED;

    if (flags & MAP_ANONYMOUS) {
        vma->vm_type = VMA_TYPE_ANON;
        vma->vm_flags |= VMA_ANON;
        vma->node = NULL;
    } else {
        vma->vm_type = VMA_TYPE_FILE;
        vfs_node_t node = current_task->fd_info->fds[fd]->node;
        vma->node = node;
        node->refcount++;
        char *fp = vfs_get_fullpath(node);
        vma->vm_name = strdup(fp);
        free(fp);
        vma->vm_offset = offset;
    }

    spin_unlock(&mgr->lock);

    uint64_t ret = 0;

    if (!(flags & MAP_ANONYMOUS)) {
        if (current_task->fd_info->fds[fd]->node->type & file_dir) {
            vma_free(vma);
            return (uint64_t)-EISDIR;
        }

        ret = (uint64_t)vfs_map(current_task->fd_info->fds[fd], start_addr,
                                aligned_len, prot, flags, offset);
    } else {
        uint64_t pt_flags = PT_FLAG_R | PT_FLAG_W | PT_FLAG_U;

        map_page_range(get_current_page_dir(true), start_addr, 0, aligned_len,
                       pt_flags);

        ret = start_addr;
    }

    if ((int64_t)ret < 0) {
        vma_free(vma);
        return ret;
    }

    if (vma_insert(mgr, vma) != 0) {
        vma_free(vma);
        return (uint64_t)-ENOMEM;
    }

    return ret;
}

uint64_t do_munmap(uint64_t addr, uint64_t size) {
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    size = (size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);

    if (check_user_overflow(addr, size)) {
        return -EFAULT;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    if (!vma_find_intersection(mgr, addr, addr + size)) {
        return -EINVAL;
    }

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
                vma_split(mgr, vma, end);
                vma_split(mgr, vma, start);
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

uint64_t sys_munmap(uint64_t addr, uint64_t size) {
    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    uint64_t ret = do_munmap(addr, size);
    spin_unlock(&mgr->lock);
    return ret;
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

static uint64_t mremap_shrink(vma_manager_t *mgr, vma_t *vma, uint64_t old_addr,
                              uint64_t old_size, uint64_t new_size) {
    if (new_size == 0) {
        // 完全删除
        vma_remove(mgr, vma);
        unmap_page_range(get_current_page_dir(true), old_addr, old_size);
        vma_free(vma);
        return 0;
    }

    // 解除尾部映射
    uint64_t unmap_start = old_addr + new_size;
    uint64_t unmap_size = old_size - new_size;

    unmap_page_range(get_current_page_dir(true), unmap_start, unmap_size);

    // 调整 VMA（如果整个 VMA 就是这个映射）
    if (vma->vm_start == old_addr && vma->vm_end == old_addr + old_size) {
        mgr->vm_used -= unmap_size;
        vma->vm_end = old_addr + new_size;
    } else if (vma->vm_end == old_addr + old_size) {
        // 缩小了 VMA 的一部分（末尾）
        mgr->vm_used -= unmap_size;
        // 需要分割或调整
    }

    return old_addr;
}

static uint64_t mremap_expand_inplace(vma_manager_t *mgr, vma_t *vma,
                                      uint64_t old_addr, uint64_t old_size,
                                      uint64_t new_size) {
    uint64_t old_end = old_addr + old_size;
    uint64_t new_end = old_addr + new_size;
    uint64_t expand_size = new_size - old_size;

    // 检查是否可以原地扩展
    bool can_expand = false;

    // 情况1：扩展后仍在当前 VMA 内
    if (new_end <= vma->vm_end) {
        can_expand = true;
    }
    // 情况2：需要扩展超出 VMA，但后面没有其他映射
    else if (old_end == vma->vm_end) {
        if (!vma_find_intersection(mgr, old_end, new_end)) {
            can_expand = true;
        }
    }

    if (!can_expand)
        return (uint64_t)-ENOMEM;

    // 执行扩展
    if (vma->vm_type == VMA_TYPE_FILE) {
        // 文件映射：使用 vfs_map
        uint64_t file_offset = vma->vm_offset + old_size;
        uint64_t prot = 0;

        if (vma->vm_flags & VMA_READ)
            prot |= PROT_READ;
        if (vma->vm_flags & VMA_WRITE)
            prot |= PROT_WRITE;
        if (vma->vm_flags & VMA_EXEC)
            prot |= PROT_EXEC;

        unmap_page_range(get_current_page_dir(true), old_addr, old_size);

        fd_t fd;
        fd.node = vma->node;
        fd.flags = 0;
        fd.offset = vma->vm_offset;

        uint64_t ret = (uint64_t)vfs_map(
            &fd, old_addr, new_size, prot,
            (vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE,
            vma->vm_offset);
        if (ret > (uint64_t)-4095UL)
            return ret;

    } else {
        // 匿名映射：分配新物理页
        uint64_t pt_flags = PT_FLAG_U;

        if (vma->vm_flags & VMA_WRITE)
            pt_flags |= PT_FLAG_W;
        if (vma->vm_flags & VMA_READ)
            pt_flags |= PT_FLAG_R;
        if (vma->vm_flags & VMA_EXEC)
            pt_flags |= PT_FLAG_X;

        // 映射新页（物理地址为 0 表示分配新页）
        map_page_range(get_current_page_dir(true), old_end, 0, expand_size,
                       pt_flags);
    }

    // 更新 VMA
    if (new_end > vma->vm_end) {
        mgr->vm_used += new_end - vma->vm_end;
        vma->vm_end = new_end;
    }

    return old_addr;
}

static uint64_t mremap_move(vma_manager_t *mgr, vma_t *old_vma,
                            uint64_t old_addr, uint64_t old_size,
                            uint64_t new_size, uint64_t flags,
                            uint64_t new_addr_hint) {
    uint64_t new_addr;

    // 确定新地址
    if (flags & MREMAP_FIXED) {
        new_addr = new_addr_hint;

        if (new_addr + new_size > USER_MMAP_END)
            return (uint64_t)-ENOMEM;

        // 类似 MAP_FIXED，需要先 unmap 冲突区域
        do_munmap(new_addr, new_size);
    } else {
        // 查找空闲地址
        new_addr = find_unmapped_area(mgr, new_addr_hint, new_size);
        if (new_addr > (uint64_t)-4095UL)
            return new_addr;
    }

    // 创建新 VMA
    vma_t *new_vma = vma_alloc();
    if (!new_vma)
        return (uint64_t)-ENOMEM;

    new_vma->vm_start = new_addr;
    new_vma->vm_end = new_addr + new_size;
    new_vma->vm_flags = old_vma->vm_flags;
    new_vma->vm_type = old_vma->vm_type;
    new_vma->node = old_vma->node;
    new_vma->shm_id = old_vma->shm_id;
    new_vma->vm_offset = old_vma->vm_offset;

    // 增加引用计数
    if (new_vma->node)
        new_vma->node->refcount++;

    // 复制名称
    if (old_vma->vm_name)
        new_vma->vm_name = strdup(old_vma->vm_name);

    // 插入新 VMA
    if (vma_insert(mgr, new_vma) != 0) {
        if (new_vma->node)
            new_vma->node->refcount--;
        if (new_vma->vm_name)
            free(new_vma->vm_name);
        vma_free(new_vma);
        return (uint64_t)-ENOMEM;
    }

    // 映射新区域并复制数据
    uint64_t prot = 0;
    if (old_vma->vm_flags & VMA_READ)
        prot |= PROT_READ;
    if (old_vma->vm_flags & VMA_WRITE)
        prot |= PROT_WRITE;
    if (old_vma->vm_flags & VMA_EXEC)
        prot |= PROT_EXEC;

    if (old_vma->vm_type == VMA_TYPE_FILE) {
        // 文件映射：重新映射文件
        fd_t fd;
        fd.node = old_vma->node;
        fd.flags = 0;
        fd.offset = old_vma->vm_offset;

        uint64_t ret = (uint64_t)vfs_map(
            &fd, new_addr, new_size, prot,
            (old_vma->vm_flags & VMA_SHARED) ? MAP_SHARED : MAP_PRIVATE,
            old_vma->vm_offset);
        if (ret > (uint64_t)-4095UL) {
            vma_remove(mgr, new_vma);
            if (new_vma->node)
                new_vma->node->refcount--;
            if (new_vma->vm_name)
                free(new_vma->vm_name);
            vma_free(new_vma);
            return ret;
        }

    } else {
        // 匿名映射：分配新物理页并复制数据
        uint64_t pt_flags = PT_FLAG_U;
        if (old_vma->vm_flags & VMA_WRITE)
            pt_flags |= PT_FLAG_W;
        if (old_vma->vm_flags & VMA_READ)
            pt_flags |= PT_FLAG_R;
        if (old_vma->vm_flags & VMA_EXEC)
            pt_flags |= PT_FLAG_X;

        // 分配新物理页
        map_page_range(get_current_page_dir(true), new_addr, 0, new_size,
                       pt_flags);

        // 复制旧数据（只复制 old_size，新扩展部分保持清零）
        memcpy((void *)new_addr, (void *)old_addr, old_size);
    }

    // 处理旧区域
    // 注意：这里需要考虑旧区域可能只是 VMA 的一部分
    if (old_vma->vm_start == old_addr &&
        old_vma->vm_end == old_addr + old_size) {
        // 整个 VMA 被移动，直接删除
        unmap_page_range(get_current_page_dir(true), old_addr, old_size);
        vma_remove(mgr, old_vma);
        vma_free(old_vma);

    } else {
        // 只移动了 VMA 的一部分，需要分割
        unmap_page_range(get_current_page_dir(true), old_addr, old_size);

        if (old_addr == old_vma->vm_start) {
            // 移动了前部
            mgr->vm_used -= old_size;
            old_vma->vm_start = old_addr + old_size;
            if (old_vma->vm_type == VMA_TYPE_FILE) {
                old_vma->vm_offset += old_size;
            }
        } else if (old_addr + old_size == old_vma->vm_end) {
            // 移动了尾部
            mgr->vm_used -= old_size;
            old_vma->vm_end = old_addr;
        } else {
            // 移动了中间部分，分成两个 VMA
            vma_t *tail_vma = vma_alloc();
            if (tail_vma) {
                tail_vma->vm_start = old_addr + old_size;
                tail_vma->vm_end = old_vma->vm_end;
                tail_vma->vm_flags = old_vma->vm_flags;
                tail_vma->vm_type = old_vma->vm_type;
                tail_vma->node = old_vma->node;
                tail_vma->shm_id = old_vma->shm_id;

                if (tail_vma->node)
                    tail_vma->node->refcount++;

                if (old_vma->vm_type == VMA_TYPE_FILE) {
                    tail_vma->vm_offset =
                        old_vma->vm_offset +
                        (old_addr + old_size - old_vma->vm_start);
                }

                if (old_vma->vm_name)
                    tail_vma->vm_name = strdup(old_vma->vm_name);

                vma_insert(mgr, tail_vma);
            }

            mgr->vm_used -= old_size;
            old_vma->vm_end = old_addr;
        }
    }

    return new_addr;
}

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr) {
    // 页对齐
    uint64_t old_addr_aligned = old_addr & ~(DEFAULT_PAGE_SIZE - 1);
    uint64_t new_addr_aligned = new_addr & ~(DEFAULT_PAGE_SIZE - 1);
    uint64_t old_size_aligned = PADDING_UP(old_size, DEFAULT_PAGE_SIZE);
    uint64_t new_size_aligned = PADDING_UP(new_size, DEFAULT_PAGE_SIZE);

    // 参数检查
    if (old_size == 0 || new_size == 0)
        return (uint64_t)-EINVAL;

    if (old_addr != old_addr_aligned)
        return (uint64_t)-EINVAL;

    // MREMAP_FIXED 必须配合 MREMAP_MAYMOVE
    if ((flags & MREMAP_FIXED) && !(flags & MREMAP_MAYMOVE))
        return (uint64_t)-EINVAL;

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;
    spin_lock(&mgr->lock);

    vma_t *vma = vma_find(mgr, old_addr_aligned);
    if (!vma || vma->vm_start != old_addr_aligned) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EINVAL;
    }

    // 验证整个区域都在 VMA 内
    if (old_addr_aligned + old_size_aligned > vma->vm_end) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-EINVAL;
    }

    if (new_size_aligned <= old_size_aligned) {
        uint64_t result = mremap_shrink(mgr, vma, old_addr_aligned,
                                        old_size_aligned, new_size_aligned);
        spin_unlock(&mgr->lock);
        return result;
    }

    if (!(flags & MREMAP_FIXED)) {
        uint64_t result = mremap_expand_inplace(
            mgr, vma, old_addr_aligned, old_size_aligned, new_size_aligned);
        if (result != (uint64_t)-ENOMEM) {
            spin_unlock(&mgr->lock);
            return result;
        }
    }

    if (!(flags & MREMAP_MAYMOVE)) {
        spin_unlock(&mgr->lock);
        return (uint64_t)-ENOMEM;
    }

    uint64_t result = mremap_move(mgr, vma, old_addr_aligned, old_size_aligned,
                                  new_size_aligned, flags, new_addr_aligned);

    spin_unlock(&mgr->lock);
    return result;
}

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset) {
    uint64_t pt_flags = PT_FLAG_U | PT_FLAG_R | PT_FLAG_W;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_page_range(
        get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), 0,
        (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    file->offset = offset;
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
