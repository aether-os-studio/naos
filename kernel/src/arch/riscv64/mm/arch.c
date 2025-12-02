#include "arch.h"
#include <drivers/kernel_logger.h>
#include <drivers/fb.h>
#include <libs/klibc.h>
#include <mm/mm.h>
#include <task/task.h>

uint64_t *get_current_page_dir(bool user) {
    (void)user;
    uint64_t satp = read_satp();
    uint64_t root_ppn = satp & SATP_PPN_MASK;

    uint64_t page_table_base = root_ppn << 12;

    return (uint64_t *)phys_to_virt(page_table_base);
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t result =
        ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_ACCESSED | ARCH_PT_FLAG_DIRTY;

    if ((flags & PT_FLAG_R) != 0) {
        result |= ARCH_PT_FLAG_READ;
    }

    if ((flags & PT_FLAG_W) != 0) {
        result |= ARCH_PT_FLAG_WRITEABLE;
    }

    if ((flags & PT_FLAG_U) != 0) {
        result |= ARCH_PT_FLAG_USER;
    }

    if ((flags & PT_FLAG_X) != 0) {
        result |= ARCH_PT_FLAG_EXEC;
    }

    return result;
}

void arch_flush_tlb(uint64_t vaddr) {
    __asm__ volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}
