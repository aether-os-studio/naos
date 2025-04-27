#pragma once

#include <stdint.h>
#include <nr.h>

void create_window(const char *title);
void get_window_info(window_info_t *info);
void destroy_window();
void write_window(uint64_t x1, uint64_t y1, uint64_t x2, uint64_t y2, uint32_t *color_map);
