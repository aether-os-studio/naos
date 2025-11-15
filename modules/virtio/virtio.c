// Copyright (C) 2025  lihanrui2913
#include "virtio.h"
#include "pci.h"
#include "mmio.h"

#include "net.h"
#include "blk.h"
#include "gpu.h"

extern virtio_driver_op_t virtio_pci_driver_op;

uint32_t virtio_begin_init(virtio_driver_t *driver,
                           uint32_t supported_features) {
    driver->op->set_status(driver->data, 0);
    driver->op->set_status(driver->data, 1 | 2);

    uint32_t features = driver->op->get_features(driver->data);
    features &= supported_features;
    driver->op->set_features(driver->data, features);

    driver->op->set_status(driver->data, 1 | 2 | 8);

    return features;
}

void virtio_finish_init(virtio_driver_t *driver) {
    driver->op->set_status(driver->data, 1 | 2 | 4 | 8);
}

int virtio_probe(pci_device_t *dev, uint32_t vendor_device_id) {
    uint16_t device_id = vendor_device_id & 0xFFFF;

    virtio_driver_t *driver = virtio_pci_driver_op.init(dev);
    if (driver) {
        printk("Found virtio pci device. type = %d\n",
               ((virtio_pci_device_t *)driver->data)->device_type);
        switch (((virtio_pci_device_t *)driver->data)->device_type) {
        case VIRTIO_DEVICE_TYPE_NETWORK:
            virtio_net_init(driver);
            break;
        case VIRTIO_DEVICE_TYPE_BLOCK:
            virtio_blk_init(driver);
            break;
        case VIRTIO_DEVICE_TYPE_GPU:
            virtio_gpu_init(driver);
            break;

        default:
            break;
        }
        dev->desc = driver;
    }

    return 0;
}

void virtio_remove(pci_device_t *dev) {}

void virtio_shutdown(pci_device_t *dev) {}

pci_driver_t virtio_pci_driver = {
    .name = "virtio",
    .class_id = 0x00000000,
    .vendor_device_id = 0x1AF40000,
    .probe = virtio_probe,
    .remove = virtio_remove,
    .shutdown = virtio_shutdown,
    .flags = PCI_DRIVER_FLAGS_NEED_SYSFS,
};

#if !defined(__x86_64__)
static int virtio_mmio_fdt_probe(fdt_device_t *fdt_dev,
                                 const char *compatible) {
    int len;
    const uint32_t *reg_prop;
    const uint32_t *irq_prop;

    reg_prop = fdt_getprop(get_dtb_ptr(), fdt_dev->node, "reg", &len);
    if (!reg_prop || len < 8) {
        printk("VirtIO MMIO: Failed to get reg property\n");
        return -1;
    }

    uint64_t base_addr = fdt32_to_cpu(reg_prop[0]);
    uint64_t size = fdt32_to_cpu(reg_prop[1]);

    if (len >= 16) {
        base_addr = ((uint64_t)fdt32_to_cpu(reg_prop[0]) << 32) |
                    fdt32_to_cpu(reg_prop[1]);
        size = ((uint64_t)fdt32_to_cpu(reg_prop[2]) << 32) |
               fdt32_to_cpu(reg_prop[3]);
    }

    uint32_t irq = 0;
    irq_prop = fdt_getprop(get_dtb_ptr(), fdt_dev->node, "interrupts", &len);
    if (irq_prop && len >= 4) {
        irq = fdt32_to_cpu(irq_prop[0]);
    }

    printk("VirtIO MMIO: Base=0x%llx, Size=0x%llx, IRQ=%d\n", base_addr, size,
           irq);

    virtio_mmio_device_t *mmio_dev = malloc(sizeof(virtio_mmio_device_t));
    if (!mmio_dev) {
        printk("VirtIO MMIO: Failed to allocate device structure\n");
        return -1;
    }

    volatile uint8_t *virt = (volatile uint8_t *)phys_to_virt(base_addr);
    map_page_range(get_current_page_dir(false), (uint64_t)virt, base_addr, size,
                   PT_FLAG_R | PT_FLAG_W |
                       PT_FLAG_UNCACHEABLE);

    mmio_dev->base = virt; // 或者通过 ioremap 映射
    mmio_dev->irq = irq;

    /* 保存到 FDT 设备的私有数据 */
    fdt_dev->driver_data = mmio_dev;

    /* 初始化 VirtIO 驱动 */
    virtio_driver_t *drv = virtio_mmio_ops.init(mmio_dev);
    if (!drv) {
        free(mmio_dev);
        return -1;
    }

    switch (((virtio_mmio_device_t *)drv->data)->device_id) {
    case VIRTIO_DEVICE_TYPE_NETWORK:
        virtio_net_init(drv);
        break;
    case VIRTIO_DEVICE_TYPE_BLOCK:
        virtio_blk_init(drv);
        break;
    case VIRTIO_DEVICE_TYPE_GPU:
        virtio_gpu_init(drv);
        break;
    default:
        break;
    }

    return 0;
}

/**
 * FDT Remove 函数
 */
static void virtio_mmio_fdt_remove(fdt_device_t *fdt_dev) {
    virtio_mmio_device_t *mmio_dev = fdt_dev->driver_data;

    if (mmio_dev) {
        printk("VirtIO MMIO: Removing device %s\n", fdt_dev->name);

        virtio_mmio_write32(mmio_dev, VIRTIO_MMIO_STATUS, 0);

        free(mmio_dev);
        fdt_dev->driver_data = NULL;
    }
}

static const char *virtio_mmio_compatible[] = {"virtio,mmio", NULL};

fdt_driver_t virtio_mmio_driver = {
    .name = "virtio-mmio",
    .compatible = virtio_mmio_compatible,
    .probe = virtio_mmio_fdt_probe,
    .remove = virtio_mmio_fdt_remove,
    .shutdown = NULL,
    .flags = 0,
};
#endif

__attribute__((visibility("default"))) int dlmain() {
    regist_pci_driver(&virtio_pci_driver);

#if !defined(__x86_64__)
    regist_fdt_driver(&virtio_mmio_driver);
#endif

    return 0;
}
