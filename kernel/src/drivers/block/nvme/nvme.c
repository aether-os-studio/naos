#include "block/block.h"
#include "drivers/bus/pci.h"
#include "drivers/block/nvme/nvme.h"
#include "drivers/kernel_logger.h"

nvme_handle_t handlers[MAX_NVME_DEVICE_NUM];

extern uint64_t nvme_read_rs(uint64_t majorid, uint64_t minorid, uint16_t qpair_id, uint64_t lba, uint64_t buffer, uint64_t bytes);
extern uint64_t nvme_write_rs(uint64_t majorid, uint64_t minorid, uint16_t qpair_id, uint64_t lba, uint64_t buffer, uint64_t bytes);

uint64_t nvme_read(void *data, uint64_t lba, void *buffer, uint64_t count)
{
    nvme_handle_t *handle = data;
    uint64_t ret = nvme_read_rs(handle->major_id, handle->minor_id, handle->qpairs[0], lba, (uint64_t)buffer, count * 512);
    if (ret == 0)
        count = 0;
    return count;
}

uint64_t nvme_write(void *data, uint64_t lba, void *buffer, uint64_t count)
{
    nvme_handle_t *handle = data;
    uint64_t ret = nvme_write_rs(handle->major_id, handle->minor_id, handle->qpairs[0], lba, (uint64_t)buffer, count * 512);
    if (ret == 0)
        count = 0;
    return count;
}

extern void nvme_init_rs(nvme_handle_t *handlers);

void nvme_init()
{
    memset(handlers, 0, sizeof(handlers));

    nvme_init_rs(handlers);

    for (uint64_t i = 0; i < MAX_NVME_DEVICE_NUM; i++)
    {
        nvme_handle_t *handle = &handlers[i];
        if (handle->valid)
        {
            regist_blkdev((char *)"nvme", handle, 512, handle->max_size, DEFAULT_PAGE_SIZE * 128, nvme_read, nvme_write);
        }
    }
}
