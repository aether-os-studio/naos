#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

spinlock_t mm_op_lock = {0};

uint64_t sys_brk(uint64_t addr)
{
    uint64_t new_brk = (addr + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (new_brk == 0)
        return current_task->brk_start;
    if (new_brk < current_task->brk_end)
        return 0;

    uint64_t start = current_task->brk_end;
    uint64_t size = new_brk - current_task->brk_end;

    map_page_range(get_current_page_dir(true), start, 0, size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    memset((void *)start, 0, size);

    current_task->brk_end = new_brk;

    return new_brk;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset)
{
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t aligned_len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t end = addr + aligned_len - 1;

    if (check_user_overflow(addr, aligned_len))
    {
        return -EFAULT;
    }

    spin_lock(&mm_op_lock);

    if (aligned_len == 0)
    {
        return (uint64_t)-EINVAL;
    }

    if (flags & MAP_FIXED)
    {
        if (interval_tree_search(current_task->mmap_regions, addr, end))
        {
            spin_unlock(&mm_op_lock);
            return (uint64_t)-ENOMEM;
        }
    }
    else
    {
        // struct mmap_region *prev = NULL;
        uint64_t gap_start = USER_MMAP_START;

        struct mmap_region *reg = interval_tree_iter_first(current_task->mmap_regions, USER_MMAP_START, USER_MMAP_END);
        while (reg)
        {
            if (reg->it_node.start - gap_start >= aligned_len)
            {
                addr = gap_start;
                end = addr + aligned_len - 1;
                break;
            }
            gap_start = reg->it_node.last + 1;
            // prev = reg;
            reg = interval_tree_iter_next(reg);
        }

        if (!addr)
        {
            addr = current_task->mmap_start;
            current_task->mmap_start += aligned_len;
        }
    }

    struct mmap_region *new_reg = malloc(sizeof(struct mmap_region));
    new_reg->it_node.start = addr;
    new_reg->it_node.last = end;
    new_reg->prot = prot;
    new_reg->flags = flags;

    interval_tree_insert(new_reg, &current_task->mmap_regions);

    if (fd < MAX_FD_NUM && current_task->fd_info->fds[fd])
    {
        fd_t *f = current_task->fd_info->fds[fd];
        uint64_t ret = (uint64_t)vfs_map(f, addr, len, prot, flags, offset);
        spin_unlock(&mm_op_lock);
        return ret;
    }
    else
    {
        uint64_t pt_flags = PT_FLAG_W | PT_FLAG_U;

        if (prot & PROT_READ)
            pt_flags |= PT_FLAG_R;
        if (prot & PROT_WRITE)
            pt_flags |= PT_FLAG_W;
        if (prot & PROT_EXEC)
            pt_flags |= PT_FLAG_X;

        map_page_range(get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), 0, (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

        spin_unlock(&mm_op_lock);

        return addr;
    }
}

uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot)
{
    if (check_user_overflow(addr, len))
    {
        return -EFAULT;
    }

    uint64_t pt_flags = PT_FLAG_U;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_change_attribute_range(get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    return 0;
}

uint64_t sys_munmap(uint64_t addr, uint64_t size)
{
    if (check_user_overflow(addr, size))
    {
        return -EFAULT;
    }

    uint64_t end = addr + size - 1;

    spin_lock(&mm_op_lock);

    struct mmap_region *reg;
    while ((reg = interval_tree_iter_first(current_task->mmap_regions, addr, end)))
    {
        interval_tree_remove(reg, &current_task->mmap_regions);
        unmap_page_range(get_current_page_dir(false), reg->it_node.start, reg->it_node.last - reg->it_node.start + 1);

        free(reg);
    }

    spin_unlock(&mm_op_lock);

    return 0;
}

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size, uint64_t flags, uint64_t new_addr)
{
    if (check_user_overflow(old_addr, old_size) || check_user_overflow(new_addr, new_size))
    {
        return -EFAULT;
    }

    uint64_t *page_dir = get_current_page_dir(true);

    if (translate_address(page_dir, old_addr) == 0)
    {
        return -EINVAL;
    }

    spin_lock(&mm_op_lock);

    uint64_t aligned_old = (old_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t aligned_new = (new_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (aligned_new < aligned_old)
    {
        unmap_page_range(page_dir, old_addr + aligned_new, aligned_old - aligned_new);
        spin_unlock(&mm_op_lock);
        return old_addr;
    }

    uint64_t extension = aligned_new - aligned_old;

    map_page_range(page_dir, old_addr + aligned_old, 0, extension,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);
    spin_unlock(&mm_op_lock);

    return old_addr;
}

void *general_map(vfs_read_t read_callback, void *file, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset)
{
    uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    // if (flags & MAP_FIXED && addr < USER_BRK_START)
    //     map_page_range(get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), addr & (~(DEFAULT_PAGE_SIZE - 1)), (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);
    // else
    map_page_range(get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), 0, (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    ssize_t ret = read_callback(file, (void *)addr, offset, len);
    if (ret < 0)
        return (void *)-ENOMEM;

    return (void *)addr;
}

uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec)
{
    if ((uintptr_t)addr % DEFAULT_PAGE_SIZE != 0 || !vec)
    {
        return -EINVAL;
    }

    spin_lock(&mm_op_lock);

    size_t npages = size / DEFAULT_PAGE_SIZE;

    for (size_t i = 0; i < npages; i++)
    {
        uint64_t page_addr = addr + i * DEFAULT_PAGE_SIZE;

        ((uint8_t *)vec)[i] = translate_address(get_current_page_dir(true), page_addr) ? 1 : 0;
    }

    spin_unlock(&mm_op_lock);

    return 0;
}
