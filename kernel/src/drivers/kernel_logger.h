#pragma once

#include <libs/klibc.h>
#include <stdarg.h>

int printk(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);

int sys_syslog(int type, const char *buf, size_t len);
