#include <mm/hhdm.h>
#include <boot/boot.h>

uint64_t physical_memory_offset = 0;

void hhdm_init() { physical_memory_offset = boot_get_hhdm_offset(); }

uint64_t get_physical_memory_offset() { return physical_memory_offset; }
