#pragma once

#include <libs/klibc.h>

size_t kb_event_bit(void *data, uint64_t request, void *arg);
size_t mouse_event_bit(void *data, uint64_t request, void *arg);
