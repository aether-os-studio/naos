#include <boot/boot.h>

struct boot_info {
    uint64_t hartid;
    uint64_t dtb_phys;
    uint64_t dtb_virt;
    uint64_t hhdm_base;
    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t kernel_phys_end;
    uint64_t kernel_virt_end;
    uint64_t root_page_table_phys;
    uint64_t root_page_table_virt;
};

extern void kmain();

void laboot_main(uint64_t hartid, void *dtb, const struct boot_info *boot) {

    kmain();
    for (;;)
        __asm__ volatile("idle 0" ::: "memory");
}
