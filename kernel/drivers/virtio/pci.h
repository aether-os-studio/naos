#pragma once

#include <libs/aether/pci.h>
#include "virtio.h"

typedef struct virtio_cap_info_t
{
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
} virtio_cap_info_t;

#define PCI_DEVICE_ID_NETWORK 0x1000
#define PCI_DEVICE_ID_BLOCK 0x1001
#define PCI_DEVICE_ID_OFFSET 0x1040

typedef struct virtio_pci_device
{
    pci_device_t *pci_dev;
    virtio_device_type_t device_type;
    virtio_cap_info_t *common_cfg;
    virtio_cap_info_t *device_cfg;
    uint64_t config_space_vaddr;
} virtio_pci_device_t;
