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
    if ((offset & (DEFAULT_PAGE_SIZE - 1)) != 0)
    {
        return (uint64_t)-EINVAL;
    }

    uint64_t aligned_len = (len + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    if (aligned_len == 0)
    {
        return (uint64_t)-EINVAL;
    }

    if (fd < MAX_FD_NUM && current_task->fds[fd] != NULL)
    {
        char *fullpath = vfs_get_fullpath(current_task->fds[fd]);
        struct fb_fix_screeninfo screen_info;
        if (!strncmp(fullpath, "/dev/fb", 7))
        {
            vfs_ioctl(current_task->fds[fd], FBIOGET_FSCREENINFO, (uint64_t)&screen_info);
            addr = screen_info.smem_start;
            map_page_range(get_current_page_dir(true), screen_info.smem_start, screen_info.smem_start, screen_info.smem_len, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);
            return addr;
        }
    }

    if (addr == 0)
    {
        addr = current_task->mmap_start;
        flags &= (~MAP_FIXED);
    }

    current_task->mmap_start += aligned_len + DEFAULT_PAGE_SIZE;
    if (current_task->mmap_start > USER_MMAP_END)
    {
        current_task->mmap_start -= aligned_len;
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

    if (fd > 2 && fd < MAX_FD_NUM)
    {
        vfs_node_t file = current_task->fds[fd];
        if (!file)
            return -EBADF;
        vfs_read(file, (void *)addr, offset, len);
    }
    else
    {
        memset((void *)addr, 0, len);
    }

    return addr;
}
