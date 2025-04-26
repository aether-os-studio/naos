#include <mm/hhdm.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_hhdm_request hhdm_request = {.id = LIMINE_HHDM_REQUEST, .revision = 0};

uint64_t physical_memory_offset = 0;

void hhdm_init()
{
    physical_memory_offset = hhdm_request.response->offset;
}

uint64_t get_physical_memory_offset()
{
    return physical_memory_offset;
}
