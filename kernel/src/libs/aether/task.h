#pragma once

#include <task/task.h>

#if defined(__x86_64__)
#include <arch/arch.h>
#endif

void enable_scheduler();
void disable_scheduler();
