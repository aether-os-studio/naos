#include "virtio.h"
#include "pci.h"

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

pci_driver_t virtio_driver = {
    .name = "virtio",
    .class_id = 0x00000000,
    .vendor_device_id = 0x1AF40000,
    .probe = virtio_probe,
    .remove = virtio_remove,
    .shutdown = virtio_shutdown,
    .flags = PCI_DRIVER_FLAGS_NEED_SYSFS,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_pci_driver(&virtio_driver);

    return 0;
}
