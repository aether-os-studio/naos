#include <arch/aarch64/acpi/acpi.h>
#include <arch/aarch64/drivers/serial.h>
#include <drivers/bus/pci.h>
#include <mm/mm.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_rsdp_request rsdp_request = {.id = LIMINE_RSDP_REQUEST, .revision = 0, .response = NULL};

uint64_t rsdp_paddr;

XSDT *xsdt;

void *find_table(const char *name)
{
    uint64_t entry_count = (xsdt->h.Length - 32) / 8;
    uint64_t *t = (uint64_t *)((char *)xsdt + offsetof(XSDT, PointerToOtherSDT));
    for (uint64_t i = 0; i < entry_count; i++)
    {
        uint64_t phys = (uint64_t)(*(t + i));
        uint64_t ptr = phys_to_virt(phys);
        map_page_range(get_current_page_dir(false), ptr, phys, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);
        uint8_t signa[5] = {0};
        memcpy(signa, ((struct ACPISDTHeader *)ptr)->Signature, 4);
        if (memcmp(signa, name, 4) == 0)
        {
            return (void *)ptr;
        }
    }
    return NULL;
}

#define load_table(name, func)                             \
    do                                                     \
    {                                                      \
        void *name = find_table(#name);                    \
        if (name == NULL)                                  \
        {                                                  \
            printk("Cannot find acpi " #name " table.\n"); \
            return;                                        \
        }                                                  \
        else                                               \
        {                                                  \
            func(name);                                    \
        }                                                  \
    } while (0);

void acpi_init()
{
    struct limine_rsdp_response *response = rsdp_request.response;
    if (response == NULL)
        return;

    rsdp_paddr = response->address;

    RSDP *rsdp = (RSDP *)rsdp_paddr;
    if (rsdp == NULL)
    {
        printk("Cannot find acpi RSDP table.\n");
        return;
    }
    rsdp = phys_to_virt(rsdp);
    map_page_range(get_current_page_dir(false), (uint64_t)rsdp, rsdp_paddr, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);

    uint64_t xsdt_paddr = rsdp->xsdt_address;

    xsdt = (XSDT *)xsdt_paddr;
    if (xsdt == NULL)
    {
        printk("Cannot find acpi XSDT table.\n");
        return;
    }
    xsdt = phys_to_virt(xsdt);
    map_page_range(get_current_page_dir(false), (uint64_t)xsdt, xsdt_paddr, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);

    load_table(SPCR, uart_setup);
    load_table(APIC, madt_setup);
    load_table(MCFG, pcie_setup);
}
