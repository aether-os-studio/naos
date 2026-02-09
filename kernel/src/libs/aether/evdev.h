#pragma once

#include <libs/klibc.h>
#include <libs/keys.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/sched.h>
#include <fs/termios.h>

void handle_kb_event(uint8_t scan_code, bool pressed, bool is_extended);
void handle_kb_scancode(uint8_t scancode, bool pressed, bool is_exteneded);
void handle_mouse_event(uint8_t flag, int8_t x, int8_t y, int8_t z);
task_t *get_kb_task();
