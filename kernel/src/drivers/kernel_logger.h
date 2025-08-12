#pragma once

#include <libs/klibc.h>
#include <stdarg.h>

#include <libs/flanterm/src/flanterm_backends/fb.h>
#include <libs/flanterm/src/flanterm.h>

extern struct flanterm_context *ft_ctx;

int printk(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
