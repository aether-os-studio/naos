#include "arch.h"
#include <drivers/kernel_logger.h>
#include <drivers/fb.h>
#include <libs/klibc.h>
#include <mm/mm.h>
#include <task/task.h>

uint64_t *get_current_page_dir(bool user) {
    uint64_t page_table_base = 0;
    asm volatile("movq %%cr3, %0" : "=r"(page_table_base));
    return (uint64_t *)phys_to_virt(page_table_base);
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t result = ARCH_PT_FLAG_VALID;

    if ((flags & PT_FLAG_W) != 0) {
        result |= ARCH_PT_FLAG_WRITEABLE;
    }

    if ((flags & PT_FLAG_U) != 0) {
        result |= ARCH_PT_FLAG_USER;
    }

    if ((flags & PT_FLAG_UNCACHEABLE) != 0 || (flags & PT_FLAG_DEVICE) != 0) {
        result |= (ARCH_PT_FLAG_PCD | ARCH_PT_FLAG_PWT);
    }

    // if ((flags & PT_FLAG_X) == 0) {
    //     result |= ARCH_PT_FLAG_NX;
    // }

    return result;
}

void arch_flush_tlb(uint64_t vaddr) {
    asm volatile("invlpg (%0)" ::"r"(vaddr) : "memory");
}

void arch_flush_tlb_all() {
    asm volatile("movq %%cr3, %%rax\n\t"
                 "movq %%rax, %%cr3\n\t"
                 :
                 :
                 : "rax", "memory");
}
