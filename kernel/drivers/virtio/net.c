#include "net.h"
#include <libs/aether/mm.h>

virtio_net_device_t *virtio_net_devices[MAX_NETDEV_NUM];
int virtio_net_idx = 0;

#define RX_BUFFER_SIZE 8192
#define RX_BUFFER_COUNT 32
static void *rx_buffers[RX_BUFFER_COUNT];

int virtio_net_init(virtio_driver_t *driver)
{
    uint32_t features = virtio_begin_init(driver, (1 << 5) | (1 << 16) | (1 << 28) | (1 << 29));

    uint32_t mac_low = driver->op->read_config_space(driver->data, offsetof(virtio_net_config_t, mac));
    uint32_t mac_high_and_status = driver->op->read_config_space(driver->data, offsetof(virtio_net_config_t, mac) + sizeof(uint32_t));
    uint32_t max_virtqueue_pairs_and_mtu = driver->op->read_config_space(driver->data, offsetof(virtio_net_config_t, max_virtqueue_pairs));

    uint8_t mac[6];
    mac[0] = mac_low & 0xFF;
    mac[1] = (mac_low >> 8) & 0xFF;
    mac[2] = (mac_low >> 16) & 0xFF;
    mac[3] = (mac_low >> 24) & 0xFF;
    mac[4] = mac_high_and_status & 0xFF;
    mac[5] = (mac_high_and_status >> 8) & 0xFF;

    uint16_t status = mac_high_and_status >> 16;

    uint16_t max_virtqueue_pairs = max_virtqueue_pairs_and_mtu & 0xFFFF;
    uint16_t mtu = (max_virtqueue_pairs_and_mtu >> 16) & 0xFFFF;

    printk("virtio_net: Got mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    virtqueue_t *send_queue = virt_queue_new(driver, 1, !!(features & (1 << 28)), !!(features & (1 << 29)));
    virtqueue_t *recv_queue = virt_queue_new(driver, 0, !!(features & (1 << 28)), !!(features & (1 << 29)));

    virtio_finish_init(driver);

    virtio_net_device_t *net_device = (virtio_net_device_t *)malloc(sizeof(virtio_net_device_t));
    memset(net_device, 0, sizeof(virtio_net_device_t));

    printk("virtio_net: Got mtu: %d\n", mtu);

    net_device->driver = driver;
    memcpy(net_device->mac, mac, 6);
    net_device->mtu = mtu;
    net_device->send_queue = send_queue;
    net_device->recv_queue = recv_queue;

    virtio_net_devices[virtio_net_idx++] = net_device;

    // Pre-allocate and populate receive buffers for polling mode
    for (int i = 0; i < RX_BUFFER_COUNT; i++)
    {
        rx_buffers[i] = alloc_frames_bytes(RX_BUFFER_SIZE);

        // Add receive buffer to receive queue
        virtio_buffer_t buf = {
            .addr = (uint64_t)rx_buffers[i],
            .size = RX_BUFFER_SIZE};
        bool writable = true;
        uint16_t desc_idx = virt_queue_add_buf(recv_queue, &buf, 1, &writable);
        if (desc_idx != 0xFFFF)
        {
            virt_queue_submit_buf(recv_queue, desc_idx);
        }
    }

    // Notify device about the receive buffers
    virt_queue_notify(driver, recv_queue);

    return 0;
}

int virtio_net_send(virtio_net_device_t *net_dev, void *data, uint32_t len)
{
    if (!net_dev || !data || len == 0 || len > net_dev->mtu)
    {
        return -1;
    }

    uint32_t total_len = sizeof(virtio_net_hdr_t) + len;
    void *send_buffer = alloc_frames_bytes(total_len);
    if (!send_buffer)
    {
        return -1;
    }

    virtio_net_hdr_t *header = (virtio_net_hdr_t *)send_buffer;
    memset(header, 0, sizeof(virtio_net_hdr_t));

    memcpy((uint8_t *)send_buffer + sizeof(virtio_net_hdr_t), data, len);

    virtio_buffer_t bufs[2];
    bufs[0].addr = (uint64_t)send_buffer;
    bufs[0].size = sizeof(virtio_net_hdr_t);
    bufs[1].addr = (uint64_t)send_buffer + sizeof(virtio_net_hdr_t);
    bufs[1].size = len;

    bool writable[2] = {false, false};
    uint16_t desc_idx = virt_queue_add_buf(net_dev->send_queue, bufs, 2, writable);
    if (desc_idx == 0xFFFF)
    {
        free_frames_bytes(send_buffer, RX_BUFFER_SIZE);
        return -1;
    }

    virt_queue_submit_buf(net_dev->send_queue, desc_idx);
    virt_queue_notify(net_dev->driver, net_dev->send_queue);

    return len;
}

int virtio_net_receive(virtio_net_device_t *net_dev, void *buffer, uint32_t buffer_size)
{
    if (!net_dev || !buffer || buffer_size == 0)
    {
        return -1;
    }

    uint32_t len;
    uint16_t desc_idx = virt_queue_get_used_buf(net_dev->recv_queue, &len);
    if (desc_idx == 0xFFFF)
    {
        return 0; // No packets available
    }

    virtio_descriptor_t *desc = &net_dev->recv_queue->desc[desc_idx];
    void *rx_data = phys_to_virt((void *)desc->addr);

    virtio_net_hdr_t *header = (virtio_net_hdr_t *)rx_data;
    uint32_t data_len = len - sizeof(virtio_net_hdr_t);

    if (data_len > buffer_size)
    {
        data_len = buffer_size;
    }

    memcpy(buffer, (uint8_t *)rx_data + sizeof(virtio_net_hdr_t), data_len);

    virtio_buffer_t buf = {
        .addr = desc->addr,
        .size = RX_BUFFER_SIZE};
    bool writable = true;
    uint16_t new_desc_idx = virt_queue_add_buf(net_dev->recv_queue, &buf, 1, &writable);
    if (new_desc_idx != 0xFFFF)
    {
        virt_queue_submit_buf(net_dev->recv_queue, new_desc_idx);
    }

    virt_queue_free_desc(net_dev->recv_queue, desc_idx);

    return data_len;
}

bool virtio_net_has_packets(virtio_net_device_t *net_dev)
{
    if (!net_dev)
    {
        return false;
    }
    return virt_queue_can_pop(net_dev->recv_queue);
}

virtio_net_device_t *virtio_net_get_device(uint32_t index)
{
    if (index >= virtio_net_idx)
    {
        return NULL;
    }
    return virtio_net_devices[index];
}

uint32_t virtio_net_get_device_count(void)
{
    return virtio_net_idx;
}
