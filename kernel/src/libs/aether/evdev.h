#pragma once

#include <libs/klibc.h>
#include <libs/keys.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/rrs.h>
#include <fs/termios.h>

void handle_kb_event(uint8_t evcode, bool pressed);
void handle_kb_scancode(uint8_t scancode, bool pressed);
void handle_mouse_event(uint8_t flag, int8_t x, int8_t y, int8_t z);
task_t *get_kb_task();
