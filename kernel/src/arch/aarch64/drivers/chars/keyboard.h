#pragma once

#include <libs/klibc.h>

size_t kb_event_bit(void *data, uint64_t request, void *arg);

struct task;
typedef struct task task_t;

extern uint8_t get_keyboard_input_queue();

void kb_char(task_t *task, char ch);
void push_kb_char(char ch);

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state);
