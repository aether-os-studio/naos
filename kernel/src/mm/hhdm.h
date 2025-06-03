#pragma once

#include <stdint.h>

extern uint64_t physical_memory_offset;

void hhdm_init();

#define phys_to_virt(addr) ((typeof(addr))((uint64_t)(addr) | physical_memory_offset))
#define virt_to_phys(addr) ((typeof(addr))((uint64_t)(addr) - physical_memory_offset))

uint64_t get_physical_memory_offset();
