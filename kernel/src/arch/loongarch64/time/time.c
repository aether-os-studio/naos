#include <arch/arch.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_date_at_boot_request boot_time_request =
    {
        .id = LIMINE_DATE_AT_BOOT_REQUEST,
        .revision = 0,
};

void time_read(tm *time)
{
    uint64_t current_ns;
    asm volatile(
        "rdtime.d %0, $r0\n"
        : "=r"(current_ns)::"memory");
    uint64_t timestamp = boot_time_request.response->timestamp + current_ns / 1000000000;
    time->timestamp = timestamp;
}

int64_t mktime(tm *time)
{
    return time->timestamp;
}

uint64_t nanoTime()
{
    uint64_t current_ns;
    asm volatile(
        "rdtime.d %0, $r0\n"
        : "=r"(current_ns)::"memory");

    return current_ns;
}
