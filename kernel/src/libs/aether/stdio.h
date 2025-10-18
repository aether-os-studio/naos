#pragma once

#include <libs/klibc.h>
#include <stdarg.h>
#include <drivers/fb.h>
#include <drivers/kernel_logger.h>

int printf(const char *fmt, ...);
extern int vsprintf(char *buf, const char *fmt, va_list args);

uint64_t get_cpu_count();
