#include "xhci_hcd.h"

int xhci_probe(pci_device_t *dev, uint32_t vendor_device_id)
{
    printf("Found XHCI controller.\n");
}

void xhci_remove(pci_device_t *dev)
{
}

void xhci_shutdown(pci_device_t *dev)
{
}

pci_driver_t xhci_hcd_driver = {
    .name = "xhci_hcd",
    .class_id = 0x000C0330,
    .vendor_device_id = 0x00000000,
    .probe = xhci_probe,
    .remove = xhci_remove,
    .shutdown = xhci_shutdown,
};

int module_init()
{
    regist_pci_driver(&xhci_hcd_driver);

    return 0;
}
