#pragma once

#include <libs/klibc.h>

extern uint64_t physical_memory_offset;

void NA_hhdm_init();

#define NA_phys_to_virt(addr) ((typeof(addr))((uint64_t)(addr) + physical_memory_offset))
#define NA_virt_to_phys(addr) ((typeof(addr))((uint64_t)(addr) - physical_memory_offset))

uint64_t NA_get_physical_memory_offset();
