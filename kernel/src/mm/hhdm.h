#pragma once

#include <stdint.h>

extern uint64_t physical_memory_offset;

void hhdm_init();

uint64_t get_physical_memory_offset();

#define phys_to_virt(addr)                                                     \
    ((addr)                                                                    \
         ? ((typeof(addr))((uint64_t)(addr) | get_physical_memory_offset()))   \
         : 0)
#define virt_to_phys(addr)                                                     \
    ((typeof(addr))((uint64_t)(addr) & ~get_physical_memory_offset()))
