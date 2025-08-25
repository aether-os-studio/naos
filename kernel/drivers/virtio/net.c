#include "net.h"

virtio_net_device_t *virtio_net_devices[MAX_NETDEV_NUM];
int virtio_net_idx = 0;

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

    return 0;
}

void virtio_net_send(virtio_net_device_t *net_device, uint8_t *data, uint32_t size)
{
    virtqueue_t *send_queue = net_device->send_queue;
    if (!data || !size)
    {
        virtio_buffer_t input;
        virtio_buffer_t *input_buffer = malloc(sizeof(virtio_buffer_t));
        input.addr = (uint64_t)input_buffer;
        input.size = sizeof(virtio_buffer_t);
        virtio_net_hdr_t *hdr = malloc(sizeof(virtio_net_hdr_t));
        input_buffer->addr = (uint64_t)hdr;
        input_buffer->size = sizeof(virtio_net_hdr_t);

        virtio_buffer_t output;
        output.addr = 0;
        output.size = 0;

        uint16_t head = virt_queue_add(send_queue, &input, NULL);

        uint16_t avail_slot = send_queue->avail_idx;
        send_queue->avail->ring[avail_slot] = head;
        send_queue->avail_idx++;
        send_queue->avail->index = send_queue->avail_idx;

        if (virt_queue_should_notify(send_queue))
        {
            net_device->driver->op->notify(net_device->driver->data, send_queue->queue_idx);
        }

        while (!virt_queue_can_pop(send_queue))
        {
            arch_yield();
        }

        virt_queue_pop_used(send_queue, head, &input, &output);
    }
    else
    {
        virtio_buffer_t input;
        virtio_buffer_t *input_buffer = malloc(sizeof(virtio_buffer_t) * 2);
        input.addr = (uint64_t)input_buffer;
        input.size = sizeof(virtio_buffer_t);
        virtio_net_hdr_t *hdr = malloc(sizeof(virtio_net_hdr_t));
        input_buffer->addr = (uint64_t)hdr;
        input_buffer->size = sizeof(virtio_net_hdr_t);
        input_buffer += 1;
        input_buffer->addr = (uint64_t)data;
        input_buffer->size = size;

        virtio_buffer_t output;
        output.addr = 0;
        output.size = 0;

        uint16_t head = virt_queue_add(send_queue, &input, &output);

        uint16_t avail_slot = send_queue->avail_idx;
        send_queue->avail->ring[avail_slot] = head;
        send_queue->avail_idx++;
        send_queue->avail->index = send_queue->avail_idx;

        if (virt_queue_should_notify(send_queue))
        {
            net_device->driver->op->notify(net_device->driver->data, send_queue->queue_idx);
        }

        while (!virt_queue_can_pop(send_queue))
        {
            arch_yield();
        }

        virt_queue_pop_used(send_queue, head, &input, &output);
    }
}
