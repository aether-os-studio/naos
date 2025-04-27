#pragma once

#include <libs/klibc.h>
#include <libs/ugui/ugui.h>

#define MAX_WINDOWS_NUM 32
#define WINDOW_OBJLIST_NUM 8

#define BUTTON_SIZE 20

typedef struct kui_window
{
    bool free;
    const char *title;
    uint64_t wid;
    uint64_t pid;
    uint64_t width;
    uint64_t height;
    UG_OBJECT objlst[WINDOW_OBJLIST_NUM];
    UG_WINDOW window;
    UG_BUTTON minimal_btn;
    UG_BUTTON close_btn;
} kui_window_t;

kui_window_t *get_free_window();
kui_window_t *create_window(const char *title, int x, int y, int w, int h, uint64_t pid);
void close_window(kui_window_t *window);

void save_background(int x, int y);
void restore_background(int x, int y);
void draw_mouse(int sx, int sy);

void window_init();
