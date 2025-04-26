#pragma once

#include <libs/flanterm/backends/fb.h>
#include <libs/flanterm/flanterm.h>
#include <libs/klibc.h>
#include <stdarg.h>

int NA_printk(const char *fmt, ...);
