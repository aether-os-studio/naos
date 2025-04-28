#include <drivers/window_manager/window_manager.h>
#include <arch/arch.h>
#include <task/task.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

struct limine_framebuffer *fb;

uint32_t background[CURSOR_HEIGHT][CURSOR_WIDTH];

char mouse[CURSOR_HEIGHT][CURSOR_WIDTH] = {
    "@.........",
    "@@........",
    "@w@.......",
    "@ww@......",
    "@www@.....",
    "@wwww@....",
    "@wwwww@...",
    "@wwwwww@..",
    "@wwwwwww@.",
    "@wwwwwwww@",
    "@wwww@@@@@",
    "@www@.....",
    "@ww@..@@@.",
    "@w@..@ww@.",
    "@@..@www@.",
    "@..@wwww@.",
    "....@wwww@",
    ".....@www@",
    "......@ww@",
    ".......@w@",
    "........@@"};

// 保存背景
void save_background(int x, int y)
{
    for (int i = 0; i < CURSOR_HEIGHT; i++)
    {
        memcpy(background[i], (uint8_t *)fb->address + (y + i) * fb->pitch + x * 4, CURSOR_WIDTH * 4);
    }
}

// 恢复背景
void restore_background(int x, int y)
{
    for (int i = 0; i < CURSOR_HEIGHT; i++)
    {
        memcpy((uint8_t *)fb->address + (y + i) * fb->pitch + x * 4, background[i], CURSOR_WIDTH * 4);
    }
}

void draw_mouse(int sx, int sy)
{
    for (int y = 0; y < CURSOR_HEIGHT; y++)
    {
        for (int x = 0; x < CURSOR_WIDTH; x++)
        {
            if (mouse[y][x] == '.')
            {
            }
            else if (mouse[y][x] == 'w')
            {
                *((uint32_t *)fb->address + (sy + y) * fb->width + (sx + x)) = 0xffffffff;
            }
            else if (mouse[y][x] == '@')
            {
                *((uint32_t *)fb->address + (sy + y) * fb->width + (sx + x)) = 0xff000000;
            }
        }
    }
}
