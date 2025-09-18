#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

spinlock_t mm_op_lock = {0};

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset)
{
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t aligned_len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (check_user_overflow(addr, aligned_len))
    {
        return -EFAULT;
    }

    if (aligned_len == 0)
    {
        return (uint64_t)-EINVAL;
    }

    if (addr == 0)
    {
        flags &= ~MAP_FIXED;
    find_free_addr:
        uint64_t page_count = aligned_len / DEFAULT_PAGE_SIZE;
        uint64_t idx = bitmap_find_range(current_task->mmap_regions, page_count, true);
        if (idx == (uint64_t)-1)
        {
            printk("Failed find range for mmap\n");
            return (uint64_t)-ENOMEM;
        }
        addr = (idx * DEFAULT_PAGE_SIZE) + USER_MMAP_START;
    }

    spin_lock(&mm_op_lock);

    if (addr >= USER_MMAP_START && addr + aligned_len <= USER_MMAP_END && !(flags & MAP_FIXED))
    {
        for (uint64_t a = addr; a < addr + aligned_len; a += DEFAULT_PAGE_SIZE)
        {
            if (bitmap_get(current_task->mmap_regions, (a - USER_MMAP_START) / DEFAULT_PAGE_SIZE) == false)
            {
                spin_unlock(&mm_op_lock);
                goto find_free_addr;
            }
        }
    }

    if (fd < MAX_FD_NUM && current_task->fd_info->fds[fd])
    {
        uint64_t ret = (uint64_t)vfs_map(current_task->fd_info->fds[fd], addr, aligned_len, prot, flags, offset);

        if (ret >= USER_MMAP_START && ret + aligned_len <= USER_MMAP_END)
        {
            bitmap_set_range(current_task->mmap_regions, (ret - USER_MMAP_START) / DEFAULT_PAGE_SIZE, (ret - USER_MMAP_START + aligned_len) / DEFAULT_PAGE_SIZE, false);
        }

        spin_unlock(&mm_op_lock);
        return ret;
    }
    else
    {
        uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

        if (prot != PROT_NONE)
        {
            if (prot & PROT_READ)
                pt_flags |= PT_FLAG_R;
            if (prot & PROT_WRITE)
                pt_flags |= PT_FLAG_W;
            if (prot & PROT_EXEC)
                pt_flags |= PT_FLAG_X;
        }

        map_page_range(get_current_page_dir(true), addr, 0, aligned_len, pt_flags);

        if (addr >= USER_MMAP_START && addr + aligned_len <= USER_MMAP_END)
        {
            bitmap_set_range(current_task->mmap_regions, (addr - USER_MMAP_START) / DEFAULT_PAGE_SIZE, (addr - USER_MMAP_START + aligned_len) / DEFAULT_PAGE_SIZE, false);
        }

        memset((void *)addr, 0, aligned_len);

        spin_unlock(&mm_op_lock);

        return addr;
    }
}

uint64_t sys_munmap(uint64_t addr, uint64_t size)
{
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    size = (size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);

    if (check_user_overflow(addr, size))
    {
        return -EFAULT;
    }

    spin_lock(&mm_op_lock);

    if (addr >= USER_MMAP_START && addr + size <= USER_MMAP_END)
    {
        for (uint64_t a = addr; a < addr + size; a += DEFAULT_PAGE_SIZE)
        {
            if (bitmap_get(current_task->mmap_regions, (a - USER_MMAP_START) / DEFAULT_PAGE_SIZE) == true)
            {
                spin_unlock(&mm_op_lock);
                return 0;
            }
        }
    }

    // unmap_page_range(get_current_page_dir(true), addr, size);
    // if (addr >= USER_MMAP_START && addr + size <= USER_MMAP_END)
    // {
    //     bitmap_set_range(current_task->mmap_regions, (addr - USER_MMAP_START) / DEFAULT_PAGE_SIZE, (addr - USER_MMAP_START + size) / DEFAULT_PAGE_SIZE, true);
    // }
    spin_unlock(&mm_op_lock);
    return 0;
}

uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot)
{
    addr = addr & (~(DEFAULT_PAGE_SIZE - 1));
    len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

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

uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size, uint64_t flags, uint64_t new_addr)
{
    old_addr = old_addr & (~(DEFAULT_PAGE_SIZE - 1));
    new_addr = new_addr & (~(DEFAULT_PAGE_SIZE - 1));
    old_size = (old_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    new_size = (new_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t old_addr_phys = translate_address(get_current_page_dir(true), old_addr);

    if (new_addr == 0)
    {
        flags &= ~MREMAP_FIXED;
    find_free_addr:
        uint64_t page_count = new_size / DEFAULT_PAGE_SIZE;
        uint64_t idx = bitmap_find_range(current_task->mmap_regions, page_count, true);
        if (idx == (uint64_t)-1)
        {
            printk("Failed find range for mmap\n");
            return (uint64_t)-ENOMEM;
        }
        new_addr = (idx * DEFAULT_PAGE_SIZE) + USER_MMAP_START;
    }

    spin_lock(&mm_op_lock);

    uint64_t pt_flags = PT_FLAG_R | PT_FLAG_W | PT_FLAG_U;

    if (new_addr >= USER_MMAP_START && new_addr + new_size <= USER_MMAP_END && !(flags & MREMAP_FIXED))
    {
        for (uint64_t addr = new_addr; addr < new_addr + new_size; addr += DEFAULT_PAGE_SIZE)
        {
            if (bitmap_get(current_task->mmap_regions, (addr - USER_MMAP_START) / DEFAULT_PAGE_SIZE) == false)
            {
                spin_unlock(&mm_op_lock);
                if (flags & MREMAP_MAYMOVE)
                {
                    goto find_free_addr;
                }
                else
                {
                    return (uint64_t)-ENOMEM;
                }
            }
        }
    }

    map_page_range(get_current_page_dir(true), new_addr & (~(DEFAULT_PAGE_SIZE - 1)), old_addr_phys, (new_size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    if (new_addr >= USER_MMAP_START && new_addr + new_size <= USER_MMAP_END)
    {
        bitmap_set_range(current_task->mmap_regions, (new_addr - USER_MMAP_START) / DEFAULT_PAGE_SIZE, (new_addr - USER_MMAP_START + new_size) / DEFAULT_PAGE_SIZE, false);
    }

    spin_unlock(&mm_op_lock);

    if (!(flags & MREMAP_DONTUNMAP))
        sys_munmap(old_addr, old_size);

    return new_addr;
}

void *general_map(vfs_read_t read_callback, fd_t *file, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset)
{
    uint64_t pt_flags = PT_FLAG_U | PT_FLAG_W;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    map_page_range(get_current_page_dir(true), addr & (~(DEFAULT_PAGE_SIZE - 1)), 0, (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), pt_flags);

    ssize_t ret = read_callback(file, (void *)addr, offset, len);
    if (ret < 0)
    {
        printk("Failed read file for mmap\n");
        return (void *)-ENOMEM;
    }

    return (void *)addr;
}

uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec)
{
    if (check_user_overflow(addr, size))
    {
        return -EFAULT;
    }

    if (size == 0)
    {
        return 0;
    }

    uint64_t start_page = addr & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t end_page = (addr + size - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    uint64_t num_pages = ((end_page - start_page) / DEFAULT_PAGE_SIZE) + 1;

    if (check_user_overflow(vec, num_pages))
    {
        return -EFAULT;
    }

    spin_lock(&mm_op_lock);

    uint64_t *page_dir = get_current_page_dir(true);
    uint64_t current_addr = start_page;

    for (uint64_t i = 0; i < num_pages; i++)
    {
        uint64_t phys_addr = translate_address(page_dir, current_addr);

        uint8_t resident = (phys_addr != 0) ? 1 : 0;

        memcpy((void *)(vec + i), &resident, sizeof(uint8_t));

        current_addr += DEFAULT_PAGE_SIZE;
    }

    spin_unlock(&mm_op_lock);
    return 0;
}
