#pragma once

#include <libs/klibc.h>

struct kui_window;
typedef struct kui_window kui_window_t;

typedef struct
{
    uint8_t buf[3], phase;
    int x, y, btn;
    char roll;
    bool left;
    bool center;
    bool right;
    kui_window_t *current_moving_window;
} mouse_dec;

void get_mouse_xy(int32_t *x, int32_t *y);
bool mouse_click_left();
bool mouse_click_right();

void mouse_init();
