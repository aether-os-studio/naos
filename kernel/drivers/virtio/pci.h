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

typedef struct virtio_pci_common_cfg_t
{
    uint32_t device_feature_select;
    uint32_t device_feature;
    uint32_t driver_feature_select;
    uint32_t driver_feature;
    uint16_t msix_config;
    uint16_t num_queues;
    uint8_t device_status;
    uint8_t config_generation;
    uint16_t queue_select;
    uint16_t queue_size;
    uint16_t queue_msix_vector;
    uint16_t queue_enable;
    uint16_t queue_notify_off;
    uint64_t queue_desc;
    uint64_t queue_driver;
    uint64_t queue_device;
} virtio_pci_common_cfg_t;

typedef struct virtio_pci_device
{
    pci_device_t *pci_dev;
    virtio_device_type_t device_type;
    virtio_cap_info_t *common_cfg;
    virtio_pci_common_cfg_t *common_cfg_bar;
    uint16_t *notify_regions;
    uint32_t notify_off_multiplier;
    virtio_cap_info_t *device_cfg;
    uint64_t config_space_vaddr;
} virtio_pci_device_t;
