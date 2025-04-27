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

    map_page_range(get_current_page_dir(), start, 0, size + DEFAULT_PAGE_SIZE * 4, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    new_brk = start + size;

    current_task->brk_end = new_brk;

    return new_brk;
}
