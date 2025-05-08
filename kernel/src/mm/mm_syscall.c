#include <mm/mm_syscall.h>

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

    new_brk = start + size;

    current_task->brk_end = new_brk;

    return new_brk;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset)
{
    if ((flags & MAP_ANONYMOUS) && fd != (uint64_t)-1)
    {
        return MAP_FAILED;
    }

    if (!(flags & MAP_ANONYMOUS) && fd == (uint64_t)-1)
    {
        return MAP_FAILED;
    }

    if ((offset & (DEFAULT_PAGE_SIZE - 1)) != 0)
    {
        return MAP_FAILED;
    }

    if (addr == 0)
    {
        addr = current_task->mmap_start;
        flags &= (~MAP_FIXED);
    }

    current_task->mmap_start += (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    uint64_t count = (len + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE;
    uint64_t vaddr = addr & ~(DEFAULT_PAGE_SIZE - 1);

    if (!count)
    {
        return 0;
    }

    for (uint64_t i = 0; i < count; i++)
    {
        uint64_t page = vaddr + DEFAULT_PAGE_SIZE * i;
        uint64_t flag = PT_FLAG_R | PT_FLAG_W | PT_FLAG_U;

        if (prot & PROT_READ)
        {
            flag |= PT_FLAG_R;
        }

        if (prot & PROT_WRITE)
        {
            flag |= PT_FLAG_W;
        }

        if (prot & PROT_EXEC)
        {
            flag |= PT_FLAG_X;
        }

        if (flags & MAP_FIXED)
        {
            map_page(get_current_page_dir(true), page, page, get_arch_page_table_flags(flag));
        }
        else
        {
            uint64_t phys = alloc_frames(1);
            if (phys == 0)
                return MAP_FAILED;
            map_page(get_current_page_dir(true), page, phys, get_arch_page_table_flags(flag));
        }
    }

    if (fd > 2 && fd < MAX_FD_NUM)
    {
        vfs_node_t file = current_task->fds[fd];
        if (!file)
            return MAP_FAILED;
        vfs_read(file, (void *)addr, offset, len);
    }
    else
    {
        memset((void *)addr, 0, len);
    }

    return addr;
}
