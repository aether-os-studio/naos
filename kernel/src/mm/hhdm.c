#include <mm/hhdm.h>
#include <boot/boot.h>
#include <mm/mm.h>

uint64_t physical_memory_offset = 0;
extern uint64_t memory_size;

void hhdm_init() { physical_memory_offset = boot_get_hhdm_offset(); }

uint64_t get_physical_memory_offset() { return physical_memory_offset; }

void *phys_to_virt(uint64_t phys_addr) {
    if (phys_addr == 0)
        return NULL;
    return (void *)(phys_addr + physical_memory_offset);
}

uint64_t virt_to_phys(const void *virt_addr) {
    uintptr_t virt = (uintptr_t)virt_addr;

    if (virt_addr == NULL)
        return 0;

    if (virt >= physical_memory_offset &&
        virt - physical_memory_offset < memory_size)
        return virt - physical_memory_offset;

    return translate_address(get_kernel_page_dir(), virt);
}
