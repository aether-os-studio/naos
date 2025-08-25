#pragma once

#include <libs/klibc.h>
#include <libs/aether/mm.h>
#include <libs/aether/pci.h>

typedef enum virtio_device_type
{
    VIRTIO_DEVICE_TYPE_NETWORK = 1,
    VIRTIO_DEVICE_TYPE_BLOCK = 2,
    VIRTIO_DEVICE_TYPE_GPU = 16,
    VIRTIO_DEVICE_INPUT = 18,
    VIRTIO_DEVICE_SOUND = 25,
} virtio_device_type_t;

struct virtio_driver;
typedef struct virtio_driver virtio_driver_t;

typedef struct virtio_driver_op
{
    virtio_driver_t *(*init)(void *data); // This data may be pci_device or mmio_device
    virtio_device_type_t (*get_device_type)(void *data);
    uint64_t (*get_features)(void *data);
    void (*set_features)(void *data, uint64_t features);
    uint32_t (*get_max_queue_size)(void *data, uint16_t queue);
    void (*notify)(void *data, uint16_t queue);
    uint32_t (*get_status)(void *data);
    void (*set_status)(void *data, uint32_t status);
    void (*queue_set)(void *data, uint16_t queue, uint32_t size, uint64_t descriptors_paddr, uint64_t driver_area_paddr, uint64_t device_area_paddr);
    bool (*queue_used)(void *data, uint16_t queue);
    bool (*requires_legacy_layout)(void *data);
    uint32_t (*read_config_space)(void *data, uint32_t offset);
    void (*write_config_space)(void *data, uint32_t offset, uint32_t value);
} virtio_driver_op_t;

struct virtio_driver
{
    void *data;
    virtio_driver_op_t *op;
};

typedef struct virtio_buffer
{
    uint64_t addr;
    uint32_t size;
} virtio_buffer_t;

struct virtqueue;
typedef struct virtqueue virtqueue_t;

typedef struct virtio_net_device
{
    virtio_driver_t *driver;
    uint8_t mac[6];
    uint16_t mtu;
    virtqueue_t *send_queue;
    virtqueue_t *recv_queue;
} virtio_net_device_t;

uint32_t virtio_begin_init(virtio_driver_t *driver, uint32_t supported_features);
void virtio_finish_init(virtio_driver_t *driver);

#define MAX_NETDEV_NUM 32
