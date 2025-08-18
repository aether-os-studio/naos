#include "arch.h"
#include <drivers/kernel_logger.h>
#include <drivers/fb.h>
#include <libs/klibc.h>
#include <mm/mm.h>
#include <task/task.h>

uint64_t *get_current_page_dir(bool user)
{
    uint64_t page_table_base = 0;
    if (user)
    {
        asm volatile("csrrd %0, 0x1d" // PGDL
                     : "=r"(page_table_base));
    }
    else
    {
        asm volatile("csrrd %0, 0x1c" // PGDH
                     : "=r"(page_table_base));
    }
    return (uint64_t *)phys_to_virt(page_table_base);
}

uint64_t get_arch_page_table_flags(uint64_t flags)
{
    uint64_t result = ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_GLOBAL;

    if ((flags & PT_FLAG_W) != 0)
    {
        result |= ARCH_PT_FLAG_DIRTY | ARCH_PT_FLAG_WRITEABLE;
    }

    if ((flags & PT_FLAG_U) != 0)
    {
        result |= ARCH_PT_FLAG_USER;
    }

    // if ((flags & PT_FLAG_X) == 0)
    // {
    //     result |= ARCH_PT_FLAG_NX;
    // }

    return result;
}

void arch_flush_tlb(uint64_t vaddr)
{
    uint64_t dummy = 0;
    asm volatile(
        "invtlb 0x1, %0, %1\n\t"
        "dbar 0\n\t"
        :
        : "r"(vaddr), "r"(dummy)
        : "memory");
}
