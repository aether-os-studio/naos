#include <libsyscall.h>
#include <aether/window.h>

void create_window(const char *title)
{
    enter_syscall((uint64_t)title, 0, 0, 0, 0, SYS_CREATE_WINDOW);
}

void destroy_window()
{
    enter_syscall(0, 0, 0, 0, 0, SYS_DESTROY_WINDOW);
}

void write_window(uint64_t x1, uint64_t y1, uint64_t x2, uint64_t y2, uint32_t *color_map)
{
    enter_syscall(x1, y1, x2, y2, (uint64_t)color_map, SYS_WRITE_WINDOW);
}

void get_window_info(window_info_t *info)
{
    enter_syscall((uint64_t)info, 0, 0, 0, 0, SYS_GET_WINDOW_INFO);
}
