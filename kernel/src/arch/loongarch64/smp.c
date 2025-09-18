#include <arch/arch.h>

__attribute__((
    used, section(".limine_requests"))) static volatile struct limine_mp_request
    mp_request = {
        .id = LIMINE_MP_REQUEST,
        .revision = 0,
        .flags = 0,
};

uint64_t cpu_count = 0;

void smp_init() { cpu_count = mp_request.response->cpu_count; }
