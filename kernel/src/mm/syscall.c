#include <mm/syscall.h>

uint64_t sys_brk(uint64_t addr)
{
    uint64_t new_brk = (addr + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (new_brk == 0)
        return current_task->brk_start;
    if (new_brk < current_task->brk_end)
        return 0;

    uint64_t start = current_task->brk_end;
    uint64_t size = new_brk - current_task->brk_end;

    map_page_range(get_current_page_dir(true), start, 0, size + 0x100000, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    new_brk = start + size;

    current_task->brk_end = new_brk;

    return new_brk;
}

uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t fd, uint64_t offset)
{
    if (addr == 0)
    {
        return current_task->brk_start;
    }

    uint64_t count = (len + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE;
    uint64_t vaddr = addr & ~(DEFAULT_PAGE_SIZE - 1);

    for (uint64_t i = 0; i < count; i++)
    {
        uint64_t page = vaddr + DEFAULT_PAGE_SIZE * i;
        uint64_t flags = PT_FLAG_U;

        if (prot & PROT_READ)
        {
            flags |= PT_FLAG_R;
        }

        if (prot & PROT_WRITE)
        {
            flags |= PT_FLAG_W;
        }

        if (prot & PROT_EXEC)
        {
            flags |= PT_FLAG_X;
        }

        map_page(get_current_page_dir(true), page, 0, get_arch_page_table_flags(flags));
    }

    if (fd > 2 && fd < MAX_FD_NUM)
    {
        vfs_node_t file = current_task->fds[fd];
        if (offset > file->size)
        {
            return (uint64_t)-EINVAL;
        }
        file->offset = offset;
        vfs_read(file, (void *)vaddr, file->offset, len);
    }

    return vaddr;
}
