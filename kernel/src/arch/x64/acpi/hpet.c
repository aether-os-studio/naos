#include <drivers/kernel_logger.h>
#include <arch/x64/acpi/acpi.h>
#include <mm/mm.h>

HpetInfo *hpet_addr;
static uint64_t hpetPeriod = 0;

uint64_t start_nanotime = 0;

void usleep(uint64_t nano)
{
    uint64_t target = nano * 1000;
    uint64_t targetTime = nanoTime();
    uint64_t after = 0;
    while (1)
    {
        uint64_t n = nanoTime();
        if (n < targetTime)
        {
            after += 0xffffffff - targetTime + n;
            targetTime = n;
        }
        else
        {
            after += n - targetTime;
            targetTime = n;
        }

        asm volatile("pause");

        if (after >= target)
        {
            return;
        }
    }
}

uint64_t nanoTime()
{
    if (hpet_addr == NULL)
        return 0;
    uint64_t mcv = hpet_addr->mainCounterValue;
    return mcv * hpetPeriod;
}

void hpet_setup(Hpet *hpet)
{
    hpet_addr = (HpetInfo *)phys_to_virt(hpet->base_address.address);
    map_page_range(get_current_page_dir(false), (uint64_t)hpet_addr, hpet->base_address.address, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);
    uint32_t counterClockPeriod = hpet_addr->generalCapabilities >> 32;
    hpetPeriod = counterClockPeriod / 1000000;
    hpet_addr->generalConfiguration |= 1;
    *(volatile uint64_t *)((uint64_t)hpet_addr + 0xf0) = 0;
    start_nanotime = nanoTime();
    printk("Setup acpi hpet table (nano_time: %#ld).", start_nanotime);
}
