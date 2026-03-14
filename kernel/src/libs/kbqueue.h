#pragma once

#include <libs/klibc.h>

bool queue_push(char c);
bool queue_pop_tmp(char *c);
bool queue_pop(char *c);
bool queue_flush();
void queue_push_string(const char *str);
int kb_available();
void kb_clear();
