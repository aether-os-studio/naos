#pragma once

#include <libs/flanterm/backends/fb.h>
#include <libs/flanterm/flanterm.h>
#include <libs/klibc.h>
#include <stdarg.h>

int printk(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
