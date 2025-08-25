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

int virtio_net_init(virtio_driver_t *driver);
