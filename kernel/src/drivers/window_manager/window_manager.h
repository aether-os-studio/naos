#pragma once

#include <libs/klibc.h>
#include <fs/vfs/list.h>
#include <arch/arch.h>

#define CURSOR_WIDTH 11
#define CURSOR_HEIGHT 22

#define GAP 4

#define BACKGROUND_COLOR 0x00000000

typedef enum
{
    CT_ROOT,
    CT_CON
} ContainerType;

typedef struct Container
{
    uint64_t pid;
    int x, y, width, height;
    uint32_t *buffer;
    ContainerType type;
    float split_ratio;
    struct Container *next;
    bool is_focused;
    bool minimized;
    bool dirty;
} Container;

typedef struct
{
    Container *root;
    Container *focused_container;
    Container *minimized_list;
    uint64_t container_count;
} Workspace;

Container *create_window_in_container(Workspace *ws, uint64_t pid);
uint64_t sys_create_window(const char *title);
uint64_t sys_destroy_window();
uint64_t sys_get_window_info(window_info_t *info);
uint64_t sys_write_window(uint64_t x1, uint64_t y1, uint64_t x2, uint64_t y2, uint32_t *color);
