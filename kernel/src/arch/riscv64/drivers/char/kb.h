#pragma once

#include <libs/klibc.h>

struct task;
typedef struct task task_t;

void kb_char(task_t *task, char ch);

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state);

void kb_finalise_stream();

size_t kb_event_bit(void *data, uint64_t request, void *arg);
size_t mouse_event_bit(void *data, uint64_t request, void *arg);
