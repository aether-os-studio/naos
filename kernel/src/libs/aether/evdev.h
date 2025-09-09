#pragma once

#include <libs/klibc.h>
#include <libs/keys.h>
#include <arch/arch.h>
#include <task/task.h>
#include <fs/termios.h>

char handle_kb_event(uint8_t scan_code, uint8_t scan_code_1, uint8_t scan_code_2);
void handle_mouse_event(uint8_t flag, int8_t x, int8_t y);
task_t *get_kb_task();
