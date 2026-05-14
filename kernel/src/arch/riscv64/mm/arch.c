#include "arch.h"
#include <arch/arch.h>
#include <boot/boot.h>
#include <limine.h>

static uint64_t riscv64_pt_levels = 0;
static uint64_t riscv64_satp_mode = 0;

uint64_t arch_page_table_levels() {
    if (riscv64_pt_levels != 0)
        return riscv64_pt_levels;

    switch (boot_get_paging_mode()) {
    case LIMINE_PAGING_MODE_RISCV_SV39:
        riscv64_pt_levels = 3;
        break;
    case LIMINE_PAGING_MODE_RISCV_SV57:
        riscv64_pt_levels = 5;
        break;
    case LIMINE_PAGING_MODE_RISCV_SV48:
    default:
        riscv64_pt_levels = 4;
        break;
    }

    return riscv64_pt_levels;
}

static uint64_t riscv64_detect_satp_mode() {
    if (riscv64_satp_mode != 0)
        return riscv64_satp_mode;

    switch (boot_get_paging_mode()) {
    case LIMINE_PAGING_MODE_RISCV_SV39:
        riscv64_satp_mode = 8;
        break;
    case LIMINE_PAGING_MODE_RISCV_SV57:
        riscv64_satp_mode = 10;
        break;
    case LIMINE_PAGING_MODE_RISCV_SV48:
    default:
        riscv64_satp_mode = 9;
        break;
    }

    return riscv64_satp_mode;
}

uint64_t riscv64_make_satp(uint64_t root_paddr) {
    return (riscv64_detect_satp_mode() << 60) | (root_paddr >> 12);
}

void riscv64_set_page_table_root(uint64_t root_paddr) {
    uint64_t satp = riscv64_make_satp(root_paddr);
    asm volatile("csrw satp, %0" : : "r"(satp) : "memory");
    arch_flush_tlb_all();
}

uint64_t *get_current_page_dir(bool user) {
    uint64_t satp;
    (void)user;
    asm volatile("csrr %0, satp" : "=r"(satp));
    uint64_t ppn = satp & ((1ULL << 44) - 1);
    return phys_to_virt(ppn << 12);
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t attr =
        ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_ACCESS | ARCH_PT_FLAG_DIRTY;

    if (flags & PT_FLAG_R)
        attr |= ARCH_PT_FLAG_READ;
    if (flags & PT_FLAG_W)
        attr |= ARCH_PT_FLAG_WRITE;
    if (flags & PT_FLAG_X)
        attr |= ARCH_PT_FLAG_EXEC;
    if (flags & PT_FLAG_U)
        attr |= ARCH_PT_FLAG_USER;
    if (flags & PT_FLAG_COW)
        attr |= ARCH_PT_FLAG_COW;

    return attr;
}

void arch_flush_tlb(uint64_t vaddr) {
    asm volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}

void arch_flush_tlb_all() {
    asm volatile("sfence.vma zero, zero" ::: "memory");
}
