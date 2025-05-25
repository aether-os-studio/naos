#include <drivers/dtb/dtb.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <libs/endian.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_dtb_request dtb_request = {
    .id = LIMINE_DTB_REQUEST,
    .revision = 0,
};

void dtb_init()
{
    if (dtb_request.response != NULL && dtb_request.response->dtb_ptr != NULL)
    {
    }
}
