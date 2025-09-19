#pragma once

#include <libs/klibc.h>
#include <stdarg.h>
#include <drivers/fb.h>

int printf(const char *fmt, ...);
extern int vsprintf(char *buf, const char *fmt, va_list args);
int vsnprintf(char *buf,size_t size,  const char *fmt, va_list args) ;
