#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

typedef struct {
    uint64_t configurationAndCapability;
    uint64_t comparatorValue;
    uint64_t fsbInterruptRoute;
    uint64_t unused;
} __attribute__((packed)) HpetTimer;

typedef struct {
    uint64_t generalCapabilities;
    uint64_t reserved0;
    uint64_t generalConfiguration;
    uint64_t reserved1;
    uint64_t generalInterruptStatus;
    uint8_t reserved3[0xc8];
    uint64_t mainCounterValue;
    uint64_t reserved4;
    HpetTimer timers[];
} __attribute__((packed)) volatile HpetInfo;

HpetInfo *hpet_addr;
static uint64_t hpetPeriod = 0;

uint64_t nano_time() {
    if (hpet_addr == NULL)
        return 0;
    uint64_t mcv = hpet_addr->mainCounterValue;
    return mcv * hpetPeriod;
}

void hpet_init() {
    struct uacpi_table hpet_table;
    uacpi_status status = uacpi_table_find_by_signature("HPET", &hpet_table);

    if (status == UACPI_STATUS_OK) {
        struct acpi_hpet *hpet = hpet_table.ptr;

        hpet_addr = (HpetInfo *)phys_to_virt(hpet->address.address);
        map_page_range(get_current_page_dir(false), (uint64_t)hpet_addr,
                       hpet->address.address, DEFAULT_PAGE_SIZE,
                       PT_FLAG_R | PT_FLAG_W);
        uint32_t counterClockPeriod = hpet_addr->generalCapabilities >> 32;
        hpetPeriod = counterClockPeriod / 1000000;
        hpet_addr->generalConfiguration |= 1UL;
        hpet_addr->mainCounterValue = 0;
        printk("Setup acpi hpet table (nano_time: %#ld).\n", nano_time());
    }
}
