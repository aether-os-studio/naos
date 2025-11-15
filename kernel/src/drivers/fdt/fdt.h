#pragma once

#include <libs/klibc.h>
#include <libs/fdt/libfdt.h>

#if !defined(__x86_64__)

void fdt_init();

#endif
