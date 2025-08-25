#include "net.h"

int virtio_net_init(virtio_driver_t *driver)
{
    virtio_begin_init(driver);

    uint32_t mac_low = driver->op->read_config_space(driver->data, offsetof(virtio_net_config_t, mac));
    uint32_t mac_high = driver->op->read_config_space(driver->data, offsetof(virtio_net_config_t, mac) + sizeof(uint32_t));

    uint8_t mac[6];
    mac[0] = mac_low & 0xFF;
    mac[1] = (mac_low >> 8) & 0xFF;
    mac[2] = (mac_low >> 16) & 0xFF;
    mac[3] = (mac_low >> 24) & 0xFF;
    mac[4] = mac_high & 0xFF;
    mac[5] = (mac_high >> 8) & 0xFF;

    printk("virtio_net: Got mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    virtio_finish_init(driver);
}
