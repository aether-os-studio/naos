#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <mm/mm.h>
#include <arch/x64/acpi/acpi.h>

#define load_table(name, func)                                \
    do                                                        \
    {                                                         \
        void *name = find_table(#name);                       \
        if (name == NULL)                                     \
        {                                                     \
            NA_printk("Cannot find acpi " #name " table.\n"); \
            return;                                           \
        }                                                     \
        else                                                  \
        {                                                     \
            func(name);                                       \
        }                                                     \
    } while (0);

uint64_t rsdp_paddr;

XSDT *xsdt;

__attribute__((used, section(".limine_requests"))) static volatile struct limine_rsdp_request rsdp_request = {.id = LIMINE_RSDP_REQUEST, .revision = 0, .response = NULL};

void *find_table(const char *name)
{
    uint64_t entry_count = (xsdt->h.Length - 32) / 8;
    uint64_t *t = (uint64_t *)((char *)xsdt + offsetof(XSDT, PointerToOtherSDT));
    for (uint64_t i = 0; i < entry_count; i++)
    {
        uint64_t phys = (uint64_t)(*(t + i));
        uint64_t ptr = NA_phys_to_virt(phys);
        NA_map_page_range(get_current_page_dir(), ptr, phys, NA_DEFAULT_PAGE_SIZE, NA_PT_FLAG_R | NA_PT_FLAG_W);
        uint8_t signa[5] = {0};
        NA_memcpy(signa, ((struct ACPISDTHeader *)ptr)->Signature, 4);
        if (NA_memcmp(signa, name, 4) == 0)
        {
            return (void *)ptr;
        }
    }
    return NULL;
}

void acpi_init()
{
    struct limine_rsdp_response *response = rsdp_request.response;

    rsdp_paddr = response->address;

    RSDP *rsdp = (RSDP *)rsdp_paddr;
    if (rsdp == NULL)
    {
        NA_printk("Cannot find acpi RSDP table.\n");
        return;
    }
    rsdp = NA_phys_to_virt(rsdp);
    NA_map_page_range(get_current_page_dir(), (uint64_t)rsdp, rsdp_paddr, NA_DEFAULT_PAGE_SIZE, NA_PT_FLAG_R | NA_PT_FLAG_W);

    uint64_t xsdt_paddr = rsdp->xsdt_address;

    xsdt = (XSDT *)xsdt_paddr;
    if (xsdt == NULL)
    {
        NA_printk("Cannot find acpi XSDT table.\n");
        return;
    }
    xsdt = NA_phys_to_virt(xsdt);
    NA_map_page_range(get_current_page_dir(), (uint64_t)xsdt, xsdt_paddr, NA_DEFAULT_PAGE_SIZE, NA_PT_FLAG_R | NA_PT_FLAG_W);

    load_table(HPET, hpet_setup);
    load_table(APIC, apic_setup);
    load_table(MCFG, pcie_setup);
    // load_table(FACP, facp_setup);
}
