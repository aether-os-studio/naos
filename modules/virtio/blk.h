#pragma once

#include "virtio.h"
#include "queue.h"

#include <stdint.h>
#include <libs/aether/block.h>

// Virtio block device configuration structure
typedef struct virtio_blk_config {
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;
    struct virtio_blk_geometry {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
    } geometry;
    uint32_t blk_size;
    struct virtio_blk_topology {
        // Number of logical blocks per physical block (log2)
        uint8_t physical_block_exp;
        // Offset of first aligned logical block
        uint8_t alignment_offset;
        // Suggested minimum I/O size in blocks
        uint16_t min_io_size;
        // Optimal (suggested maximum) I/O size in blocks
        uint32_t opt_io_size;
    } topology;
    uint8_t writeback;
    uint8_t unused0[3];
    uint32_t max_discard_sectors;
    uint32_t max_discard_seg;
    uint32_t discard_sector_alignment;
    uint32_t max_write_zeroes_sectors;
    uint32_t max_write_zeroes_seg;
    uint8_t write_zeroes_may_unmap;
    uint8_t unused1[3];
} virtio_blk_config_t;

// Virtio block request header
typedef struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} virtio_blk_req_t;

// Virtio block request types
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1
#define VIRTIO_BLK_T_FLUSH 4
#define VIRTIO_BLK_T_DISCARD 11
#define VIRTIO_BLK_T_WRITE_ZEROES 13

// Virtio block request status
#define VIRTIO_BLK_S_OK 0
#define VIRTIO_BLK_S_IOERR 1
#define VIRTIO_BLK_S_UNSUPP 2

// Virtio block device structure
typedef struct virtio_blk_device {
    virtio_driver_t *driver;
    uint64_t capacity;
    uint32_t block_size;
    virtqueue_t *request_queue;
    uint32_t sector_size;
} virtio_blk_device_t;

// Maximum number of block devices
#define MAX_VIRTIO_BLKDEV_NUM 32

// Function declarations
int virtio_blk_init(virtio_driver_t *driver);
int virtio_blk_read(virtio_blk_device_t *blk_dev, uint64_t sector, void *buffer,
                    uint32_t count);
int virtio_blk_write(virtio_blk_device_t *blk_dev, uint64_t sector,
                     const void *buffer, uint32_t count);
int virtio_blk_flush(virtio_blk_device_t *blk_dev);
virtio_blk_device_t *virtio_blk_get_device(uint32_t index);
uint32_t virtio_blk_get_device_count(void);
