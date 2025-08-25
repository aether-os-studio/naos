#pragma once

#include <libs/klibc.h>
#include "virtio.h"

#define DESC_FLAGS_NEXT (1 << 0)
#define DESC_FLAGS_WRITE (1 << 1)
#define DESC_FLAGS_INDIRECT (1 << 2)

typedef struct virtio_descriptor
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} virtio_descriptor_t;

typedef enum virtio_descriptor_buffer_direction
{
    VIRTIO_DESC_BUFFER_DIR_DRIVER_TO_DEVICE,
    VIRTIO_DESC_BUFFER_DIR_DEVICE_TO_DRIVER,
    VIRTIO_DESC_BUFFER_DIR_BOTH,
} virtio_descriptor_buffer_direction_t;

static inline void virtio_descriptor_set_buf(virtio_descriptor_t *desc, void *addr, uint32_t len, virtio_descriptor_buffer_direction_t dir, uint16_t extra_flags)
{
    desc->addr = (uint64_t)addr;
    desc->len = len;
    desc->flags = extra_flags | ((dir == VIRTIO_DESC_BUFFER_DIR_DEVICE_TO_DRIVER) ? DESC_FLAGS_WRITE : (dir == VIRTIO_DESC_BUFFER_DIR_DRIVER_TO_DEVICE) ? 0
                                                                                                                                                        // Should be error
                                                                                                                                                        : 0);
}

#define RING_SIZE 64

typedef struct virtio_avail_ring
{
    uint16_t flags;
    uint16_t index;
    uint16_t ring[RING_SIZE];
    uint16_t used_event;
} virtio_avail_ring_t;

typedef struct virtio_used_elem
{
    uint32_t id;
    uint32_t len;
} virtio_used_elem_t;

typedef struct virtio_used_ring
{
    uint16_t flags;
    uint16_t index;
    virtio_used_elem_t ring[RING_SIZE];
    uint16_t avail_event;
} virtio_used_ring_t;

typedef struct virtqueue_legacy
{
    uint64_t paddr;
    uint32_t size;
    uint64_t avail_offset;
    uint64_t used_offset;
} virtqueue_legacy_t;

typedef struct virtqueue_modern
{
    uint64_t driver_to_device_paddr;
    uint32_t driver_to_device_size;
    uint64_t device_to_driver_paddr;
    uint32_t device_to_driver_size;
    uint64_t avail_offset;
} virtqueue_modern_t;

typedef struct virtqueue
{
    virtio_descriptor_t *desc;
    virtio_avail_ring_t *avail;
    virtio_used_ring_t *used;

    bool is_modern;
    union
    {
        virtqueue_legacy_t *legacy;
        virtqueue_modern_t *modern;
    } inner;

    uint16_t queue_idx;
    uint16_t num_used;
    uint16_t free_head;
    virtio_descriptor_t desc_shadow[RING_SIZE];
    uint16_t avail_idx;
    uint16_t last_used_idx;
    bool event_idx;
} virtqueue_t;

virtqueue_t *virt_queue_new(virtio_driver_t *driver, uint16_t queue_idx, bool indirect, bool event_idx);
