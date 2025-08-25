#include "pci.h"

extern virtio_driver_op_t virtio_pci_driver_op;

virtio_device_type_t get_device_type(uint16_t device_id)
{
    switch (device_id)
    {
    case PCI_DEVICE_ID_NETWORK:
        return VIRTIO_DEVICE_TYPE_NETWORK;
    case PCI_DEVICE_ID_BLOCK:
        return VIRTIO_DEVICE_TYPE_BLOCK;
    default:
        return (virtio_device_type_t)(device_id - PCI_DEVICE_ID_OFFSET);
    }
}

virtio_driver_t *virtio_pci_init(void *data)
{
    pci_device_t *device = (pci_device_t *)data;
    uint16_t vendor_id = device->vendor_id;
    uint16_t device_id = device->device_id;
    if (vendor_id != 0x1AF4)
    {
        return NULL;
    }
    virtio_device_type_t device_type = get_device_type(device_id);

    virtio_cap_info_t *common_cfg = NULL;
    virtio_cap_info_t *device_cfg = NULL;

    uint32_t old_tmp = 0;
    uint32_t tmp = 0;
    uint32_t cap_offset = device->capability_point;
    while (1)
    {
        old_tmp = tmp;
        tmp = device->op->read(device->bus, device->slot, device->func, device->segment, cap_offset);
        if ((tmp & 0xff) != 0x09)
        {
            if (((tmp & 0xff00) >> 8))
            {
                cap_offset = (tmp & 0xff00) >> 8;
                continue;
            }
            else
                break;
        }

        uint32_t capability_header = device->op->read(device->bus, device->slot, device->func, device->segment, cap_offset);
        uint16_t private_header = (capability_header >> 16) & 0xFF;

        virtio_cap_info_t *cap_info = malloc(sizeof(virtio_cap_info_t));
        memset(cap_info, 0, sizeof(virtio_cap_info_t));
        cap_info->bar = device->op->read(device->bus, device->slot, device->func, device->segment, cap_offset + 0x04);
        cap_info->offset = device->op->read(device->bus, device->slot, device->func, device->segment, cap_offset + 0x08);
        cap_info->length = device->op->read(device->bus, device->slot, device->func, device->segment, cap_offset + 0x0C);

        if ((private_header >> 8) == 1)
        {
            common_cfg = cap_info;
        }
        else if ((private_header >> 8) == 1)
        {
            device_cfg = cap_info;
        }

        cap_offset = (tmp & 0xff00) >> 8;
    }

    virtio_pci_device_t *pci = malloc(sizeof(virtio_pci_device_t));
    memset(pci, 0, sizeof(virtio_pci_device_t));
    pci->pci_dev = device;
    pci->device_type = device_type;
    pci->common_cfg = common_cfg;
    pci->device_cfg = device_cfg;

    uint64_t config_space_vaddr = 0;

    if (device_cfg)
    {
        pci_bar_t *bar = &device->bars[pci->device_cfg->bar];
        uint64_t bar_paddr = bar->address + pci->device_cfg->offset;
        if (bar_paddr == 0)
            goto done;
        uint64_t bar_vaddr = phys_to_virt(bar_paddr);
        map_page_range(get_current_page_dir(false), bar_vaddr, bar_paddr, pci->device_cfg->length, PT_FLAG_R | PT_FLAG_W);
        config_space_vaddr = bar_vaddr;
    }

done:
    pci->config_space_vaddr = config_space_vaddr;

    virtio_driver_t *driver = malloc(sizeof(virtio_driver_t));
    driver->data = (void *)pci;
    driver->op = &virtio_pci_driver_op;
}

virtio_device_type_t virtio_pci_get_device_type(void *data)
{
    virtio_pci_device_t *pci = (virtio_pci_device_t *)data;
    return pci->device_type;
}

virtio_driver_op_t virtio_pci_driver_op = {
    .init = virtio_pci_init,
    .get_device_type = virtio_pci_get_device_type,
};
