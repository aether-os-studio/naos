#pragma once

#include <libs/klibc.h>

#define MOUSE_BBIT 0x01
#define MOUSE_ABIT 0x02

void get_mouse_xy(int32_t *x, int32_t *y);
bool mouse_click_left();
bool mouse_click_right();

void mouse_init();

size_t mouse_event_bit(void *data, uint64_t request, void *arg);
