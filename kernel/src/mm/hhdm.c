#include <mm/hhdm.h>
#include <boot/boot.h>

uint64_t physical_memory_offset = 0;

void hhdm_init() { physical_memory_offset = boot_get_hhdm_offset(); }

uint64_t get_physical_memory_offset() { return physical_memory_offset; }

void *phys_to_virt(uint64_t phys_addr) {
    if (phys_addr == 0)
        return NULL;
    return (void *)(phys_addr + physical_memory_offset);
}

uint64_t virt_to_phys(const void *virt_addr) {
    if (virt_addr == NULL)
        return 0;
    return (uint64_t)virt_addr - physical_memory_offset;
}
