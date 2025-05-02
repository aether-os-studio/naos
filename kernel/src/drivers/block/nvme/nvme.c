#include "drivers/bus/pci.h"
#include "drivers/block/nvme/nvme.h"
#include "drivers/kernel_logger.h"

NVME_NAMESPACE *namespaces[MAX_NVME_DEV_NUM];
uint64_t nvme_device_num = 0;

void nvme_init()
{
    pci_device_t *devs[MAX_NVME_DEV_NUM];
    uint32_t num;

    pci_find_class(devs, &num, 0x010802);

    if (num == 0)
    {
        printk("No NVME controller found\n");
        return;
    }

    for (uint32_t i = 0; i < num; i++)
    {
        pci_device_t *dev = devs[i];

        nvme_driver_init(dev->bars[0].address, dev->bars[0].size);
    }
}
