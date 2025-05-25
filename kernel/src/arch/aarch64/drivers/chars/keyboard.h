#pragma once

#include <libs/klibc.h>

uint8_t get_keyboard_input();

size_t kb_event_bit(void *data, uint64_t request, void *arg);
