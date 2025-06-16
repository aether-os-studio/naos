#pragma once

#include <libs/klibc.h>
#include <stdarg.h>

int printk(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
