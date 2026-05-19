#pragma once

#include <libs/klibc.h>

extern uint64_t physical_memory_offset;

void hhdm_init();

uint64_t get_physical_memory_offset();

/**
 * Convert a physical address into the direct-map virtual alias.
 * Notes: this assumes the address belongs to memory covered by the HHDM. It is
 * not a generic "make any bus address dereferenceable" helper; PCI BARs and
 * other MMIO regions usually need their own mapping rules.
 */
void *phys_to_virt(uint64_t phys_addr);
/**
 * Convert a direct-mapped kernel virtual address back to a physical address.
 * Notes: this is only valid for addresses that actually live in the direct map.
 * Passing arbitrary kernel pointers here is a good way to get a plausible but
 * meaningless number.
 */
uint64_t virt_to_phys(const void *virt_addr);
