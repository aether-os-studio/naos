#pragma once

#include <stdint.h>

extern uint64_t physical_memory_offset;

void hhdm_init();

uint64_t get_physical_memory_offset();

void *phys_to_virt(uint64_t phys_addr);
uint64_t virt_to_phys(const void *virt_addr);
