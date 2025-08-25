#pragma once

#include "virtio.h"
#include "queue.h"

typedef struct virtio_net_config
{
    uint8_t mac[6];
    uint16_t status;
    uint16_t max_virtqueue_pairs;
    uint16_t mtu;
} virtio_net_config_t;

typedef struct virtio_net_hdr
{
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} virtio_net_hdr_t;

int virtio_net_init(virtio_driver_t *driver);
int virtio_net_send(virtio_net_device_t *net_dev, void *data, uint32_t len);
int virtio_net_receive(virtio_net_device_t *net_dev, void *buffer, uint32_t buffer_size);
bool virtio_net_has_packets(virtio_net_device_t *net_dev);
virtio_net_device_t *virtio_net_get_device(uint32_t index);
uint32_t virtio_net_get_device_count(void);
