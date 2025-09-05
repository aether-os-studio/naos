#pragma once

#include <libs/klibc.h>
#include <stdarg.h>
#include <libs/flanterm/flanterm_backends/fb.h>
#include <libs/flanterm/flanterm.h>

extern struct flanterm_context *ft_ctx;

int printk(const char *fmt, ...);
int serial_fprintk(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);

int sys_syslog(int type, const char *buf, size_t len);
