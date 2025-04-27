#include <drivers/window_manager/window_manager.h>
#include <arch/arch.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

struct limine_framebuffer *fb;

UG_GUI g;

kui_window_t windows[MAX_WINDOWS_NUM];

#define CURSOR_WIDTH 11
#define CURSOR_HEIGHT 22

uint32_t background[CURSOR_HEIGHT][CURSOR_WIDTH];

kui_window_t *get_free_window()
{
    for (uint64_t i = 0; i < MAX_WINDOWS_NUM; i++)
    {
        if (windows[i].free)
        {
            windows[i].free = false;
            windows[i].wid = i;
            return &windows[i];
        }
    }

    return NULL;
}

void window_callback(UG_MESSAGE *message)
{
}

kui_window_t *create_window(const char *title, int x, int y, int w, int h, uint64_t pid)
{
    kui_window_t *window = get_free_window();
    window->title = title;
    window->pid = pid;
    window->width = w;
    window->height = h;
    UG_WindowCreate(&window->window, window->objlst, WINDOW_OBJLIST_NUM, window_callback);
    UG_WindowSetTitleText(&window->window, (char *)window->title);
    UG_WindowSetTitleTextFont(&window->window, &FONT_8X14);

    UG_WindowResize(&window->window, x, y, x + w, y + h);

    UG_ButtonCreate(&window->window, &window->close_btn, BTN_ID_0, w - (5 * 12) - 5, -BUTTON_SIZE, w - 5, 0);
    UG_ButtonSetText(&window->window, BTN_ID_0, "CLOSE");
    UG_ButtonSetStyle(&window->window, BTN_ID_0, BTN_STYLE_2D | BTN_STYLE_NO_BORDERS);

    UG_ButtonCreate(&window->window, &window->minimal_btn, BTN_ID_1, w - (7 * 12) - (5 * 12) - 5, -BUTTON_SIZE, w - (5 * 12) - 5, 0);
    UG_ButtonSetText(&window->window, BTN_ID_1, "MINIMAL");
    UG_ButtonSetStyle(&window->window, BTN_ID_1, BTN_STYLE_2D | BTN_STYLE_NO_BORDERS);

    UG_WindowShow(&window->window);

    return window;
}

void close_window(kui_window_t *window)
{
    UG_WindowDelete(&window->window);
    windows[window->wid].pid = 0;
    windows[window->wid].free = true;
}

void fb_put_pixel(UG_S16 x, UG_S16 y, UG_COLOR color)
{
    *((uint32_t *)fb->address + y * fb->width + x) = color;
}

void window_init()
{
    memset(windows, 0, sizeof(windows));
    for (uint64_t i = 0; i < MAX_WINDOWS_NUM; i++)
    {
        windows[i].free = true;
    }
    if (framebuffer_request.response->framebuffer_count == 0)
    {
        while (1)
        {
            arch_pause();
        }
    }
    memset(background, 0, sizeof(background));
    fb = framebuffer_request.response->framebuffers[0];
    UG_Init(&g, fb_put_pixel, fb->width, fb->height);
    UG_SelectGUI(&g);
    UG_FontSelect(&FONT_8X14);
}

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

void windowmanager_thread()
{
    window_init();

    int32_t x;
    int32_t y;
    get_mouse_xy(&x, &y);

    save_background(x, y);

    draw_mouse(x, y);

    create_window("title", 300, 200, 600, 400, 0);

    while (1)
    {
        UG_Update();

        int32_t x;
        int32_t y;
        get_mouse_xy(&x, &y);
        if (mouse_click_left())
        {
            UG_TouchUpdate(x, y, TOUCH_STATE_PRESSED);
        }
        else
        {
            UG_TouchUpdate(x, y, TOUCH_STATE_RELEASED);
        }

        arch_pause();
    }
}