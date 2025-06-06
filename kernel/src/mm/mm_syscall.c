#include <mm/mm_syscall.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

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

    if (addr == 0)
    {
        addr = current_task->mmap_start;
        flags &= (~MAP_FIXED);
    }

    if (aligned_len == 0)
    {
        return (uint64_t)-EINVAL;
    }

    if (fd < MAX_FD_NUM && current_task->fds[fd])
    {
        vfs_node_t node = current_task->fds[fd]->node;
        return (uint64_t)vfs_map(node, addr, len, prot, flags, offset);
    }
    else
    {
        current_task->mmap_start += (aligned_len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
        if (current_task->mmap_start > USER_MMAP_END)
        {
            current_task->mmap_start -= (aligned_len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
            return (uint64_t)-ENOMEM;
        }

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

        return addr;
    }
}

uint64_t sys_munmap(uint64_t addr, uint64_t size)
{
    unmap_page_range(get_current_page_dir(false), addr, size);
    return 0;
}

void *general_map(vfs_read_t read_callback, void *file, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset)
{
    current_task->mmap_start += (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    if (current_task->mmap_start > USER_MMAP_END)
    {
        current_task->mmap_start -= (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
        return (void *)-ENOMEM;
    }

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
