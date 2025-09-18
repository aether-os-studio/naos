#include "blk.h"
#include <libs/aether/mm.h>
#include <libs/klibc.h>

virtio_blk_device_t *virtio_blk_devices[MAX_VIRTIO_BLKDEV_NUM];
int virtio_blk_idx = 0;

uint64_t virtio_read(void *data, uint64_t lba, void *buffer, uint64_t count) {
    virtio_blk_device_t *blk = data;
    uint64_t ret = virtio_blk_read(blk, lba, buffer, count);
    return ret / blk->block_size;
}

uint64_t virtio_write(void *data, uint64_t lba, void *buffer, uint64_t count) {
    virtio_blk_device_t *blk = data;
    uint64_t ret = virtio_blk_write(blk, lba, buffer, count);
    virtio_blk_flush(blk);
    return ret / blk->block_size;
}

int virtio_blk_init(virtio_driver_t *driver) {
    uint32_t supported_features = (1 << 5) | (1 << 9) | (1 << 28) | (1 << 29);
    uint32_t features = virtio_begin_init(driver, supported_features);

    // Read block device configuration
    virtio_blk_config_t config;
    memset(&config, 0, sizeof(config));

    // Read configuration space
    for (uint32_t i = 0; i < sizeof(virtio_blk_config_t) / sizeof(uint32_t);
         i++) {
        uint32_t value =
            driver->op->read_config_space(driver->data, i * sizeof(uint32_t));
        memcpy((uint8_t *)&config + i * sizeof(uint32_t), &value,
               sizeof(uint32_t));
    }

    // Create request queue
    virtqueue_t *request_queue = virt_queue_new(
        driver, 0, !!(features & (1 << 28)), !!(features & (1 << 29)));
    if (!request_queue) {
        printk("virtio_blk: Failed to create request queue\n");
        return -1;
    }

    virtio_finish_init(driver);

    // Create block device structure
    virtio_blk_device_t *blk_device =
        (virtio_blk_device_t *)malloc(sizeof(virtio_blk_device_t));
    memset(blk_device, 0, sizeof(virtio_blk_device_t));

    blk_device->driver = driver;
    blk_device->capacity = config.capacity;
    blk_device->block_size =
        config.blk_size ? config.blk_size : 512; // Default to 512 bytes
    blk_device->request_queue = request_queue;
    blk_device->sector_size = 512; // Standard sector size

    printk("virtio_blk: Found block device with capacity %llu sectors (%llu "
           "MB), block size: %u bytes\n",
           config.capacity,
           (config.capacity * blk_device->sector_size) / (1024 * 1024),
           blk_device->block_size);

    // Store device in global array
    if (virtio_blk_idx < MAX_BLKDEV_NUM) {
        virtio_blk_devices[virtio_blk_idx++] = blk_device;
    } else {
        printk("virtio_blk: Maximum number of block devices reached\n");
        free(blk_device);
        return -1;
    }

    regist_blkdev((char *)"virtio-blk", blk_device, blk_device->block_size,
                  config.capacity * blk_device->sector_size,
                  DEFAULT_PAGE_SIZE * 32, virtio_read, virtio_write);

    return 0;
}

int virtio_blk_read(virtio_blk_device_t *blk_dev, uint64_t sector, void *buffer,
                    uint32_t count) {
    if (!blk_dev || !buffer || count == 0) {
        return -1;
    }

    uint32_t total_size = count * blk_dev->sector_size;
    // Allocate separate buffers for header, data, and status
    virtio_blk_req_t *req_header =
        (virtio_blk_req_t *)alloc_frames_bytes(sizeof(virtio_blk_req_t));
    void *data_buffer = alloc_frames_bytes(total_size);
    uint8_t *status_byte = (uint8_t *)alloc_frames_bytes(sizeof(uint8_t));

    if (!req_header || !data_buffer || !status_byte) {
        if (req_header)
            free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        if (data_buffer)
            free_frames_bytes(data_buffer, total_size);
        if (status_byte)
            free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    // Setup request header
    req_header->type = VIRTIO_BLK_T_IN;
    req_header->reserved = 0;
    req_header->sector = sector;

    // Setup status byte
    *status_byte = 0xFF; // Initialize to invalid status

    virtio_buffer_t bufs[3];
    bufs[0].addr = (uint64_t)req_header;
    bufs[0].size = sizeof(virtio_blk_req_t);
    bufs[1].addr = (uint64_t)data_buffer;
    bufs[1].size = total_size;
    bufs[2].addr = (uint64_t)status_byte;
    bufs[2].size = sizeof(uint8_t);

    bool writable[3] = {false, true, true};
    uint16_t desc_idx =
        virt_queue_add_buf(blk_dev->request_queue, bufs, 3, writable);
    if (desc_idx == 0xFFFF) {
        printk("virtio_blk: Failed to add buffer to queue\n");
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(data_buffer, total_size);
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    virt_queue_submit_buf(blk_dev->request_queue, desc_idx);
    virt_queue_notify(blk_dev->driver, blk_dev->request_queue);

    // Wait for completion
    uint32_t len;
    uint16_t used_desc_idx;
    while ((used_desc_idx = virt_queue_get_used_buf(blk_dev->request_queue,
                                                    &len)) == 0xFFFF) {
        // Busy wait for completion
        arch_pause();
    }

    // Check status
    if (*status_byte != VIRTIO_BLK_S_OK) {
        printk("virtio_blk: Read failed with status %d\n", *status_byte);
        virt_queue_free_desc(blk_dev->request_queue, used_desc_idx);
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(data_buffer, total_size);
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    // Copy data to user buffer
    memcpy(buffer, data_buffer, total_size);

    // Free the descriptor
    virt_queue_free_desc(blk_dev->request_queue, used_desc_idx);

    free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
    free_frames_bytes(data_buffer, total_size);
    free_frames_bytes(status_byte, sizeof(uint8_t));

    return total_size;
}

int virtio_blk_write(virtio_blk_device_t *blk_dev, uint64_t sector,
                     const void *buffer, uint32_t count) {
    if (!blk_dev || !buffer || count == 0) {
        return -1;
    }

    uint32_t total_size = count * blk_dev->sector_size;
    // Allocate separate buffers for header, data, and status
    virtio_blk_req_t *req_header =
        (virtio_blk_req_t *)alloc_frames_bytes(sizeof(virtio_blk_req_t));
    void *data_buffer = alloc_frames_bytes(total_size);
    uint8_t *status_byte = (uint8_t *)alloc_frames_bytes(sizeof(uint8_t));

    if (!req_header || !data_buffer || !status_byte) {
        if (req_header)
            free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        if (data_buffer)
            free_frames_bytes(data_buffer, total_size);
        if (status_byte)
            free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    // Setup request header
    req_header->type = VIRTIO_BLK_T_OUT;
    req_header->reserved = 0;
    req_header->sector = sector;

    // Copy data to data buffer
    memcpy(data_buffer, (void *)buffer, total_size);

    // Setup status byte
    *status_byte = 0xFF; // Initialize to invalid status

    virtio_buffer_t bufs[3];
    bufs[0].addr = (uint64_t)req_header;
    bufs[0].size = sizeof(virtio_blk_req_t);
    bufs[1].addr = (uint64_t)data_buffer;
    bufs[1].size = total_size;
    bufs[2].addr = (uint64_t)status_byte;
    bufs[2].size = sizeof(uint8_t);

    bool writable[3] = {false, false, true};
    uint16_t desc_idx =
        virt_queue_add_buf(blk_dev->request_queue, bufs, 3, writable);
    if (desc_idx == 0xFFFF) {
        printk("virtio_blk: Failed to add buffer to queue\n");
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(data_buffer, total_size);
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    virt_queue_submit_buf(blk_dev->request_queue, desc_idx);
    virt_queue_notify(blk_dev->driver, blk_dev->request_queue);

    // Wait for completion
    uint32_t len;
    uint16_t used_desc_idx;
    while ((used_desc_idx = virt_queue_get_used_buf(blk_dev->request_queue,
                                                    &len)) == 0xFFFF) {
        // Busy wait for completion
        arch_pause();
    }

    // Check status
    if (*status_byte != VIRTIO_BLK_S_OK) {
        printk("virtio_blk: Write failed with status %d\n", *status_byte);
        virt_queue_free_desc(blk_dev->request_queue, used_desc_idx);
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(data_buffer, total_size);
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    // Free the descriptor
    virt_queue_free_desc(blk_dev->request_queue, used_desc_idx);

    free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
    free_frames_bytes(data_buffer, total_size);
    free_frames_bytes(status_byte, sizeof(uint8_t));
    return total_size;
}

int virtio_blk_flush(virtio_blk_device_t *blk_dev) {
    if (!blk_dev) {
        return -1;
    }

    // Allocate separate buffers for header and status
    virtio_blk_req_t *req_header =
        (virtio_blk_req_t *)alloc_frames_bytes(sizeof(virtio_blk_req_t));
    uint8_t *status_byte = (uint8_t *)alloc_frames_bytes(sizeof(uint8_t));

    if (!req_header || !status_byte) {
        if (req_header)
            free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        if (status_byte)
            free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    // Setup flush request header
    req_header->type = VIRTIO_BLK_T_FLUSH;
    req_header->reserved = 0;
    req_header->sector = 0;

    // Setup status byte
    *status_byte = 0xFF; // Initialize to invalid status

    virtio_buffer_t bufs[2];
    bufs[0].addr = (uint64_t)req_header;
    bufs[0].size = sizeof(virtio_blk_req_t);
    bufs[1].addr = (uint64_t)status_byte;
    bufs[1].size = sizeof(uint8_t);

    bool writable[2] = {false, true};
    uint16_t desc_idx =
        virt_queue_add_buf(blk_dev->request_queue, bufs, 2, writable);
    if (desc_idx == 0xFFFF) {
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    virt_queue_submit_buf(blk_dev->request_queue, desc_idx);
    virt_queue_notify(blk_dev->driver, blk_dev->request_queue);

    // Wait for completion
    uint32_t len;
    uint16_t used_desc_idx;
    while ((used_desc_idx = virt_queue_get_used_buf(blk_dev->request_queue,
                                                    &len)) == 0xFFFF) {
        // Busy wait for completion
        arch_pause();
    }

    // Check status
    if (*status_byte != VIRTIO_BLK_S_OK) {
        printk("virtio_blk: Flush failed with status %d\n", *status_byte);
        free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
        free_frames_bytes(status_byte, sizeof(uint8_t));
        return -1;
    }

    free_frames_bytes(req_header, sizeof(virtio_blk_req_t));
    free_frames_bytes(status_byte, sizeof(uint8_t));
    virt_queue_free_desc(blk_dev->request_queue, used_desc_idx);
    return 0;
}

virtio_blk_device_t *virtio_blk_get_device(uint32_t index) {
    if (index >= virtio_blk_idx) {
        return NULL;
    }
    return virtio_blk_devices[index];
}

uint32_t virtio_blk_get_device_count(void) { return virtio_blk_idx; }
