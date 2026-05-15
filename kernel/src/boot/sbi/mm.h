#pragma once

#include <libs/klibc.h>

#define SBI_PAGE_SIZE 4096UL
#define SBI_KERNEL_PHYS_BASE 0x80000000ULL
#define SBI_KERNEL_VIRT_BASE 0xffffffff80000000ULL
#define SBI_KERNEL_VMA (SBI_KERNEL_VIRT_BASE - SBI_KERNEL_PHYS_BASE)
#define SBI_HHDM_OFFSET 0xffffffc000000000ULL

void boot_mm_init(void);
uint64_t boot_mm_map_dtb(uint64_t dtb_paddr);
void boot_mm_map_hhdm_range(uint64_t paddr, uint64_t size);
uint64_t boot_mm_pt_pool_paddr(void);
uint64_t boot_mm_pt_pool_size(void);
