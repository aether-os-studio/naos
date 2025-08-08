#include "nvme.h"

int nvme_probe(pci_device_t *dev, uint32_t vendor_device_id)
{
    printf("Found NVME controller.\n");

    NVME_CONTROLLER *nvme = nvme_driver_init(dev->bars[0].address, dev->bars[0].size);
    if (!nvme)
        return -1;

    dev->desc = nvme;
}

void nvme_remove(pci_device_t *dev)
{
}

void nvme_shutdown(pci_device_t *dev)
{
}

pci_driver_t nvme_driver = {
    .name = "nvme_driver",
    .class_id = 0x00010802,
    .vendor_device_id = 0x00000000,
    .probe = nvme_probe,
    .remove = nvme_remove,
    .shutdown = nvme_shutdown,
};

__attribute__((visibility("default"))) int module_init()
{
    regist_pci_driver(&nvme_driver);

    return 0;
}
