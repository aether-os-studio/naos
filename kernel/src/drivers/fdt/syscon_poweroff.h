#pragma once

#include <libs/klibc.h>

#if !defined(__x86_64__)
void syscon_poweroff_init(void);
void syscon_poweroff_shutdown(void);
#endif
