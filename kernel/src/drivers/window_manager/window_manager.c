#include <drivers/window_manager/window_manager.h>
#include <arch/arch.h>
#include <task/task.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

struct limine_framebuffer *fb;

Workspace ws = {0};

Container *create_container(Container *parent, ContainerType type)
{
    Container *c = malloc(sizeof(Container));
    c->type = type;
    c->split_ratio = 0.5f;
    c->next = NULL;
    if (parent)
    {
        c->next = parent->next;
        parent->next = c;
    }
    c->is_focused = false;
    c->minimized = false;
    c->dirty = true;
    c->x = 0;
    c->y = 0;

    return c;
}

void ws_init(Workspace *ws)
{
    ws->root = create_container(NULL, CT_ROOT);
    ws->root->width = fb->width;
    ws->root->height = fb->height;
    ws->root->next = NULL;
    ws->root->buffer = alloc_frames_bytes((ws->root->width - GAP * 2) * (ws->root->height - GAP * 2) * sizeof(uint32_t));
    memset(ws->root->buffer, 0x00, ws->root->width * ws->root->height * sizeof(uint32_t));
    ws->focused_container = ws->root;
    ws->minimized_list = NULL;
    ws->container_count = 0;
}

Container *create_window_in_container(Workspace *ws, uint64_t pid)
{
    ws->container_count++;
    uint64_t count = ws->container_count;
    Container *container = ws->root;
    container->is_focused = false;

    // 横向分割
    Container *new_container = create_container(container, CT_CON);
    new_container->pid = pid;

    // 计算宽高
    uint64_t hor_container_count = count;
    container->width = fb->width / hor_container_count;
    container->height = fb->height;
    uint64_t idx = 0;
    container->is_focused = false;
    for (Container *next = container->next; next; next = next->next)
    {
        next->x = idx;
        next->y = 0;
        if (next->buffer)
            free_frames_bytes(next->buffer, (next->width - GAP * 2) * (next->height - GAP * 2) * sizeof(uint32_t));
        next->width = fb->width / hor_container_count;
        next->height = fb->height;
        next->buffer = alloc_frames_bytes((next->width - GAP * 2) * (next->height - GAP * 2) * sizeof(uint32_t));
        memset(next->buffer, 0x00, next->width * next->height * sizeof(uint32_t));
        idx += container->width;
        next->is_focused = false;
        for (uint64_t i = 0; i < MAX_TASK_NUM; i++)
        {
            if (!tasks[i])
                continue;
            tasks[i]->signal |= SIGMASK(SIGWRSZ);
        }
        next->dirty = true;
    }
    new_container->is_focused = true;

    return new_container;
}

void destroy_container(Container *container)
{
    free_frames_bytes(container->buffer, (container->width - GAP * 2) * (container->height - GAP * 2) * sizeof(uint32_t));
    memset(container, 0, sizeof(Container));
    free(container);
}

void destroy_window_in_container(Workspace *ws, uint64_t pid)
{
    Container *next = NULL;
    for (next = ws->root->next; next; next = next->next)
    {
        if (next->pid == pid)
        {
            break;
        }
    }

    if (!next)
    {
        return;
    }

    Container *prev = NULL;
    for (prev = ws->root->next; prev && prev->next != next; prev = prev->next)
    {
    }

    if (prev)
    {
        prev->next = next->next;
    }
    destroy_container(next);
}

void memset32(uint32_t *buffer, uint32_t color, int xsize)
{
    for (int i = 0; i < xsize; i++)
    {
        buffer[i] = color;
    }
}

void draw_rect(int x1, int y1, int x2, int y2, uint32_t color)
{
    int xsize = x2 - x1 + 1;

    uint8_t *buffer = malloc(xsize * fb->bpp / 8);
    memset32((uint32_t *)buffer, color, xsize);

    for (int y = y1; y < y2; y++)
    {
        memcpy((uint8_t *)fb->address + y * fb->pitch + x1 * fb->bpp / 8, buffer, (xsize - 1) * fb->bpp / 8);
    }

    free(buffer);
}

void update_container(Container *container)
{
    uint32_t color = container->is_focused ? 0x87CEFA : 0xFFFFFF;

    // 顶边（高度为 GAP）
    draw_rect(container->x, container->y, container->x + container->width - GAP, container->y + GAP, color);
    // 底边（高度为 GAP）
    draw_rect(container->x, container->y + container->height - GAP, container->x + container->width - GAP, container->y + container->height, color);
    // 左边（宽度为 GAP）
    draw_rect(container->x, container->y, container->x + GAP, container->y + container->height, color);
    // 右边（宽度为 GAP）
    draw_rect(container->x + container->width - GAP, container->y, container->x + container->width, container->y + container->height, color);

    for (int offy = 0; offy < container->height - GAP * 2; offy++)
    {
        memcpy((uint32_t *)fb->address + (container->y + GAP + offy) * fb->width + container->x + GAP, container->buffer + offy * container->width, (container->width - GAP * 2) * fb->bpp / 8);
    }
}

void update_containers(Workspace *ws)
{
    for (Container *container = ws->root->next; container; container = container->next)
    {
        if (container->dirty)
        {
            update_container(container);
            container->dirty = false;
        }
    }
}

Container *get_container_by_pid(Workspace *ws, uint64_t pid)
{
    Container *container = NULL;
    for (container = ws->root->next; container; container = container->next)
        if (container->pid == pid)
            break;

    return container;
}

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

extern bool system_initialized;

void windowmanager_thread()
{
    while (system_initialized)
    {
        arch_pause();
    }

    if (framebuffer_request.response->framebuffer_count == 0)
    {
        task_exit(0);
    }

    fb = framebuffer_request.response->framebuffers[0];

    ws_init(&ws);

    int32_t x;
    int32_t y;
    get_mouse_xy(&x, &y);

    save_background(x, y);

    draw_mouse(x, y);

    arch_input_dev_init();

    while (1)
    {
        update_containers(&ws);

        arch_pause();
    }
}

uint64_t sys_create_window(const char *title)
{
    (void)title;
    if (current_task->current_container)
    {
        return (uint64_t)-EALREADY;
    }
    Container *container = create_window_in_container(&ws, current_task->pid);
    current_task->current_container = container;

    return 0;
}

uint64_t sys_destroy_window()
{
    destroy_window_in_container(&ws, current_task->pid);
    current_task->current_container = NULL;

    return 0;
}

uint64_t sys_get_window_info(window_info_t *info)
{
    Container *ct = get_container_by_pid(&ws, current_task->pid);

    info->width = ct->width - GAP * 2;
    info->height = ct->height - GAP * 2;

    return 0;
}

uint64_t sys_write_window(uint64_t x1, uint64_t y1, uint64_t x2, uint64_t y2, uint32_t *color)
{
    Container *ct = get_container_by_pid(&ws, current_task->pid);

    uint64_t xsize = x2 - x1 + 1;

    if ((int64_t)x1 < 0)
    {
        x1 = 0;
    }
    if ((int64_t)y1 < 0)
    {
        y1 = 0;
    }
    if (x2 > (uint64_t)ct->width)
    {
        x2 = (uint64_t)ct->width;
    }
    if (y2 > (uint64_t)ct->height)
    {
        y2 = (uint64_t)ct->height;
    }
    for (uint64_t y = y1; y < y2; y++)
    {
        memcpy(ct->buffer + y * ct->width + x1, color + (y - y1) * xsize, xsize * sizeof(uint32_t));
    }

    ct->dirty = true;

    return xsize * (y2 - y1 + 1) * sizeof(uint32_t);
}
