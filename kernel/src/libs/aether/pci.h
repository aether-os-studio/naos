#pragma once

#include "../klibc.h"
#include "../../drivers/bus/pci.h"
#if defined(__x86_64__)
#include "../../drivers/bus/msi.h"
#endif

#define PCI_DRIVER_FLAGS_NEED_SYSFS (1 << 0)

typedef struct pci_driver {
    const char *name;
    uint32_t class_id, vendor_device_id;
    int (*probe)(pci_device_t *dev, uint32_t vendor_device_id);
    void (*remove)(pci_device_t *dev);
    void (*shutdown)(pci_device_t *dev);
    int flags;
} pci_driver_t;

#define MAX_PCI_DRIVERS 256

int regist_pci_driver(pci_driver_t *driver);
