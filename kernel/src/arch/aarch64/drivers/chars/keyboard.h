#pragma once

#include <libs/klibc.h>

uint8_t get_keyboard_input();

size_t kb_event_bit(void *data, uint64_t request, void *arg);

struct task;
typedef struct task task_t;

extern uint8_t get_virtio_keyboard_input();

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state);
