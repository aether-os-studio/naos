#include <libs/klibc.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_date_at_boot_request boot_time_request =
    {
        .id = LIMINE_DATE_AT_BOOT_REQUEST,
        .revision = 0,
};

#define TIMESTAMP_OFFSET (((1970UL - 1900UL) * 365UL + 17UL) * 24UL * 60UL * 60UL)

uint64_t get_counter()
{
    uint64_t val;
    asm volatile("mrs %0, CNTPCT_EL0" : "=r"(val));
    return val;
}

uint32_t get_freq()
{
    uint32_t freq;
    asm volatile("mrs %0, CNTFRQ_EL0" : "=r"(freq));
    return freq;
}

uint64_t time_read()
{
    uint64_t counter = get_counter();
    uint32_t freq = get_freq();
    uint64_t elapsed_seconds = counter / (uint64_t)freq;
    return TIMESTAMP_OFFSET + boot_time_request.response->timestamp + elapsed_seconds;
}
