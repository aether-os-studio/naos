// Copyright (C) 2025-2026  lihanrui2913
#include "pci.h"

extern virtio_driver_op_t virtio_pci_driver_op;

virtio_device_type_t get_device_type(uint16_t device_id) {
    switch (device_id) {
    case PCI_DEVICE_ID_NETWORK:
        return VIRTIO_DEVICE_TYPE_NETWORK;
    case PCI_DEVICE_ID_BLOCK:
        return VIRTIO_DEVICE_TYPE_BLOCK;
    default:
        return (virtio_device_type_t)(device_id - PCI_DEVICE_ID_OFFSET);
    }
}

virtio_driver_t *virtio_pci_init(void *data) {
    pci_device_t *device = (pci_device_t *)data;
    uint16_t vendor_id = device->vendor_id;
    uint16_t device_id = device->device_id;
    if (vendor_id != 0x1AF4) {
        return NULL;
    }
    virtio_device_type_t device_type = get_device_type(device_id);

    virtio_cap_info_t *common_cfg = NULL;
    virtio_cap_info_t *notify_cfg = NULL;
    virtio_cap_info_t *device_cfg = NULL;

    uint32_t notify_off_multiplier = 0;
    uint64_t host_visible_shm_paddr = 0;
    uint64_t host_visible_shm_size = 0;

    uint32_t tmp = 0;
    uint32_t cap_offset = device->capability_point;
    while (1) {
        tmp = device->op->read32(device->bus, device->slot, device->func,
                                 device->segment, cap_offset);
        if ((tmp & 0xff) != 0x09) {
            if (((tmp & 0xff00) >> 8)) {
                cap_offset = (tmp & 0xff00) >> 8;
                continue;
            } else
                break;
        }

        uint8_t cfg_type =
            device->op->read8(device->bus, device->slot, device->func,
                              device->segment, cap_offset + 0x03);
        uint8_t bar = device->op->read8(device->bus, device->slot, device->func,
                                        device->segment, cap_offset + 0x04);
        uint8_t cap_id =
            device->op->read8(device->bus, device->slot, device->func,
                              device->segment, cap_offset + 0x05);
        uint32_t cap_offset_lo =
            device->op->read32(device->bus, device->slot, device->func,
                               device->segment, cap_offset + 0x08);
        uint32_t cap_length_lo =
            device->op->read32(device->bus, device->slot, device->func,
                               device->segment, cap_offset + 0x0C);

        virtio_cap_info_t *cap_info = NULL;
        if (cfg_type == 1 || cfg_type == 2 || cfg_type == 4) {
            cap_info = malloc(sizeof(virtio_cap_info_t));
            if (!cap_info) {
                break;
            }
            memset(cap_info, 0, sizeof(virtio_cap_info_t));
            cap_info->bar = bar;
            cap_info->offset = cap_offset_lo;
            cap_info->length = cap_length_lo;
        }

        if (cfg_type == 1) {
            common_cfg = cap_info;
        } else if (cfg_type == 4) {
            device_cfg = cap_info;
        } else if (cfg_type == 2) {
            notify_cfg = cap_info;
            notify_off_multiplier =
                device->op->read32(device->bus, device->slot, device->func,
                                   device->segment, cap_offset + 0x10);
        } else {
            if (cap_info) {
                free(cap_info);
            }
            if (cfg_type == 8 && cap_id == 1 && bar < 6) {
                uint64_t cap_offset_hi =
                    device->op->read32(device->bus, device->slot, device->func,
                                       device->segment, cap_offset + 0x10);
                uint64_t cap_length_hi =
                    device->op->read32(device->bus, device->slot, device->func,
                                       device->segment, cap_offset + 0x14);
                uint64_t shm_offset = cap_offset_lo | (cap_offset_hi << 32);
                uint64_t shm_length = cap_length_lo | (cap_length_hi << 32);
                if (shm_length && device->bars[bar].address) {
                    host_visible_shm_paddr =
                        device->bars[bar].address + shm_offset;
                    host_visible_shm_size = shm_length;
                }
            }
        }

        cap_offset = (tmp & 0xff00) >> 8;
    }

    virtio_pci_device_t *pci = malloc(sizeof(virtio_pci_device_t));
    memset(pci, 0, sizeof(virtio_pci_device_t));
    pci->pci_dev = device;
    pci->device_type = device_type;
    pci->common_cfg = common_cfg;
    pci->device_cfg = device_cfg;

    uint64_t common_cfg_vaddr = 0;

    if (common_cfg) {
        pci_bar_t *bar = &device->bars[pci->common_cfg->bar];
        uint64_t bar_paddr = bar->address + pci->common_cfg->offset;
        if (bar_paddr == 0)
            goto done;
        uint64_t bar_vaddr = phys_to_virt(bar_paddr);
        map_page_range(get_current_page_dir(false), bar_vaddr, bar_paddr,
                       pci->common_cfg->length,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        common_cfg_vaddr = bar_vaddr;
    } else {
        if (common_cfg)
            free(common_cfg);
        if (notify_cfg)
            free(notify_cfg);
        if (device_cfg)
            free(device_cfg);
        free(pci);
        return NULL;
    }

    uint64_t notify_cfg_vaddr = 0;

    if (notify_cfg) {
        pci_bar_t *bar = &device->bars[notify_cfg->bar];
        uint64_t bar_paddr = bar->address + notify_cfg->offset;
        if (bar_paddr == 0)
            goto done;
        uint64_t bar_vaddr = phys_to_virt(bar_paddr);
        map_page_range(get_current_page_dir(false), bar_vaddr, bar_paddr,
                       notify_cfg->length,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        notify_cfg_vaddr = bar_vaddr;
    } else {
        if (common_cfg)
            free(common_cfg);
        if (notify_cfg)
            free(notify_cfg);
        if (device_cfg)
            free(device_cfg);
        free(pci);
        return NULL;
    }

    uint64_t config_space_vaddr = 0;

    if (device_cfg) {
        pci_bar_t *bar = &device->bars[pci->device_cfg->bar];
        uint64_t bar_paddr = bar->address + pci->device_cfg->offset;
        if (bar_paddr == 0)
            goto done;
        uint64_t bar_vaddr = phys_to_virt(bar_paddr);
        map_page_range(get_current_page_dir(false), bar_vaddr, bar_paddr,
                       pci->device_cfg->length,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        config_space_vaddr = bar_vaddr;
    } else {
        if (common_cfg)
            free(common_cfg);
        if (notify_cfg)
            free(notify_cfg);
        if (device_cfg)
            free(device_cfg);
        free(pci);
        return NULL;
    }

done:
    pci->notify_off_multiplier = notify_off_multiplier;
    pci->host_visible_shm_paddr = host_visible_shm_paddr;
    pci->host_visible_shm_size = host_visible_shm_size;

    pci->common_cfg_bar = (virtio_pci_common_cfg_t *)common_cfg_vaddr;
    pci->notify_regions = (uint16_t *)notify_cfg_vaddr;
    pci->config_space_vaddr = config_space_vaddr;

    virtio_driver_t *driver = malloc(sizeof(virtio_driver_t));
    memset(driver, 0, sizeof(virtio_driver_t));
    driver->data = (void *)pci;
    driver->op = &virtio_pci_driver_op;
    return driver;
}

virtio_device_type_t virtio_pci_get_device_type(void *data) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    return pci->device_type;
}

uint64_t virtio_pci_get_features(void *data) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->device_feature_select = 0;
    uint32_t features_low = pci->common_cfg_bar->device_feature;
    pci->common_cfg_bar->device_feature_select = 1;
    uint32_t features_high = pci->common_cfg_bar->device_feature;
    return (uint64_t)features_low | ((uint64_t)features_high << 32);
}

void virtio_pci_set_features(void *data, uint64_t features) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->device_feature_select = 0;
    uint32_t features_low = features & 0xFFFFFFFF;
    pci->common_cfg_bar->driver_feature_select = 0;
    pci->common_cfg_bar->driver_feature = features_low;
    pci->common_cfg_bar->device_feature_select = 1;
    uint32_t features_high = (features >> 32) & 0xFFFFFFFF;
    pci->common_cfg_bar->driver_feature_select = 1;
    pci->common_cfg_bar->driver_feature = features_high;
}

uint32_t virtio_pci_get_max_queue_size(void *data, uint16_t queue) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->queue_select = queue;
    return pci->common_cfg_bar->queue_size;
}

void virtio_pci_notify(void *data, uint16_t queue) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->queue_select = queue;
    uint16_t notify_off = pci->common_cfg_bar->queue_notify_off;
    uint64_t offset_bytes = (uint64_t)notify_off * pci->notify_off_multiplier;
    uint64_t index = offset_bytes / sizeof(uint16_t);
    pci->notify_regions[index] = queue;
}

uint32_t virtio_pci_get_status(void *data) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    return pci->common_cfg_bar->device_status;
}

void virtio_pci_set_status(void *data, uint32_t status) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->device_status = status;
}

void virtio_pci_queue_set(void *data, uint16_t queue, uint32_t size,
                          uint64_t descriptors_paddr,
                          uint64_t driver_area_paddr,
                          uint64_t device_area_paddr) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->queue_select = queue;
    pci->common_cfg_bar->queue_size = size;
    pci->common_cfg_bar->queue_desc = descriptors_paddr;
    pci->common_cfg_bar->queue_driver = driver_area_paddr;
    pci->common_cfg_bar->queue_device = device_area_paddr;
    pci->common_cfg_bar->queue_enable = 1;
}

bool virtio_pci_queue_used(void *data, uint16_t queue) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    pci->common_cfg_bar->queue_select = queue;
    return (pci->common_cfg_bar->queue_enable == 1);
}

bool virtio_pci_requires_legacy_layout(void *data) { return false; }

uint32_t virtio_pci_read_config_space(void *data, uint32_t offset) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    return *((uint32_t *)(pci->config_space_vaddr + offset));
}

void virtio_pci_write_config_space(void *data, uint32_t offset,
                                   uint32_t value) {
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    *((uint32_t *)(pci->config_space_vaddr + offset)) = value;
}

virtio_driver_op_t virtio_pci_driver_op = {
    .init = virtio_pci_init,
    .get_device_type = virtio_pci_get_device_type,
    .get_features = virtio_pci_get_features,
    .set_features = virtio_pci_set_features,
    .get_max_queue_size = virtio_pci_get_max_queue_size,
    .notify = virtio_pci_notify,
    .get_status = virtio_pci_get_status,
    .set_status = virtio_pci_set_status,
    .queue_set = virtio_pci_queue_set,
    .queue_used = virtio_pci_queue_used,
    .requires_legacy_layout = virtio_pci_requires_legacy_layout,
    .read_config_space = virtio_pci_read_config_space,
    .write_config_space = virtio_pci_write_config_space,
};
