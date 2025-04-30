#include <arch/aarch64/acpi/acpi.h>
#include <mm/mm.h>

uint64_t gic_base_virt = 0;
uint64_t gic_base_address = 0;

void madt_setup(MADT *madt)
{
    if (!madt)
        return;

    uint64_t current = 0;
    for (;;)
    {
        if (current + ((uint32_t)sizeof(MADT) - 1) >= madt->h.Length)
        {
            break;
        }
        MadtHeader *header = (MadtHeader *)((uint64_t)(&madt->entries) + current);
        if (header->entry_type == ACPI_MADT_TYPE_GICD)
        {
            GicdEntry *gicd = (GicdEntry *)((uint64_t)(&madt->entries) + current);
            gic_base_address = gicd->base_address;
            break;
        }
        current += (uint64_t)header->length;
    }

    if (gic_base_address)
    {
        gic_base_virt = phys_to_virt(gic_base_address);
        map_page_range(get_current_page_dir(false), gic_base_address, gic_base_address, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);
    }
}

uint64_t gic_get_redistributor_addr()
{
}
