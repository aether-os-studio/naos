#include "arch.h"
#include <drivers/logger.h>
#include <libs/klibc.h>
#include <mm/mm.h>
#include <task/task.h>
#include <irq/irq_manager.h>

uint64_t arch_page_table_levels() { return ARCH_MAX_PT_LEVEL; }

uint64_t *get_current_page_dir(bool user) {
    uint64_t page_table_base = 0;
    (void)user;
    asm volatile("movq %%cr3, %0" : "=r"(page_table_base));
    return (uint64_t *)phys_to_virt(page_table_base);
}

void set_current_page_dir(bool user, uint64_t pgdir) {
    (void)user;
    asm volatile("movq %0, %%cr3" ::"r"(pgdir) : "memory");
}

void arch_page_table_init(void) {
    memset(get_current_page_dir(false), 0, PAGE_SIZE / 2);
}

uint64_t arch_page_table_root_entries(int level) {
    uint64_t entries = (1UL << ARCH_PT_OFFSET_PER_LEVEL);
    if ((uint64_t)level == arch_page_table_levels())
        entries >>= 1;
    return entries;
}

uint64_t arch_make_page_table_entry(uint64_t paddr, uint64_t flags) {
    return ARCH_MAKE_PDE(paddr,
                         ARCH_PT_TABLE_FLAGS | (flags & ARCH_PT_FLAG_USER));
}

void arch_page_table_prepare_new(uint64_t *root) {
    memset(root, 0, PAGE_SIZE);
    arch_page_table_copy_kernel(root, get_kernel_page_dir());
}

void arch_page_table_copy_kernel(uint64_t *dst, uint64_t *src) {
    uint64_t user_entries = (1UL << ARCH_PT_OFFSET_PER_LEVEL) >> 1;
    memcpy(dst + user_entries, src + user_entries, PAGE_SIZE / 2);
}

bool arch_page_table_flags_writable(uint64_t flags) {
    return (flags & ARCH_PT_FLAG_WRITEABLE) != 0;
}

uint64_t arch_page_table_flags_make_cow(uint64_t flags) {
    return (flags | ARCH_PT_FLAG_COW) & ~ARCH_PT_FLAG_WRITEABLE;
}

uint64_t arch_page_table_flags_make_writable(uint64_t flags) {
    return (flags | ARCH_PT_FLAG_WRITEABLE) & ~ARCH_PT_FLAG_COW;
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t result = ARCH_PT_FLAG_VALID;

    if ((flags & PT_FLAG_W) != 0) {
        result |= ARCH_PT_FLAG_WRITEABLE;
    }

    if ((flags & PT_FLAG_U) != 0) {
        result |= ARCH_PT_FLAG_USER;
    }

    if ((flags & PT_FLAG_X) == 0) {
        result |= ARCH_PT_FLAG_NX;
    }

    if ((flags & PT_FLAG_UNCACHEABLE) != 0 || (flags & PT_FLAG_DEVICE) != 0) {
        result |= (ARCH_PT_FLAG_PCD | ARCH_PT_FLAG_PWT);
    }

    if ((flags & PT_FLAG_COW) != 0) {
        result |= ARCH_PT_FLAG_COW;
    }

    return result;
}

void arch_flush_tlb(uint64_t vaddr) {
    asm volatile("invlpg (%0)" ::"r"(PADDING_DOWN(vaddr, PAGE_SIZE))
                 : "memory");
}

void arch_flush_tlb_all() {
    asm volatile("movq %%cr3, %%rax\n\t"
                 "movq %%rax, %%cr3\n\t" ::
                     : "rax", "memory");
}
