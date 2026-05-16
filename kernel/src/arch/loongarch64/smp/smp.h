#pragma once

#include <libs/klibc.h>
#include <arch/loongarch64/cpu_local.h>

extern uint64_t cpu_count;

void smp_init();

#define current_cpu_id loongarch64_current_cpu_id()
