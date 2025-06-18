#pragma once

#include "drivers/bus/pci.h"

#define MAX_NVME_DEVICE_NUM 32
#define MAX_QPAIR_NUM 32

typedef struct nvme_handle
{
    uint64_t major_id;
    uint64_t minor_id;
    uint16_t qpairs[MAX_QPAIR_NUM];
    uint64_t max_size;
    bool valid;
} nvme_handle_t;

uint32_t NVMETransfer(nvme_handle_t *handle, void *buf, uint64_t lba, uint32_t count, uint32_t write);

void nvme_driver_init(uint64_t bar0, uint64_t bar_size);

void nvme_init();
