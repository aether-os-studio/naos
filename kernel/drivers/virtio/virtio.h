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
    uint16_t (*notify)(void *data, uint16_t queue);
    uint32_t (*get_status)(void *data);
    void (*set_status)(void *data, uint32_t status);
    void (*queue_set)(void *data, uint16_t queue, uint32_t size, uint64_t descriptors_paddr, uint64_t driver_area_paddr, uint64_t device_area_paddr);
    bool (*queue_used)(void *data, uint16_t queue);
} virtio_driver_op_t;

struct virtio_driver
{
    void *data;
    virtio_driver_op_t *op;
};
