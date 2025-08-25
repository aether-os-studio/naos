#include "queue.h"

void queue_part_sizes(uint16_t queue_size, uint64_t *desc_size, uint64_t *avail_size, uint64_t *used_size)
{
    *desc_size = queue_size * sizeof(virtio_descriptor_t);
    *avail_size = sizeof(uint16_t) * (3 + queue_size);
    *used_size = sizeof(uint16_t) * 3 + sizeof(virtio_used_elem_t) * queue_size;
}

#define QUEUE_SIZE 2048

virtqueue_t *virt_queue_new(virtio_driver_t *driver, uint16_t queue_idx, bool indirect, bool event_idx)
{
    if (driver->op->queue_used(driver->data, queue_idx))
        return NULL;

    virtqueue_t *queue = malloc(sizeof(virtqueue_t));
    memset(queue, 0, sizeof(virtqueue_t));

    if (driver->op->requires_legacy_layout(driver->data))
    {
        queue->is_modern = false;
        uint64_t desc_size, avail_size, used_size;
        queue_part_sizes(QUEUE_SIZE, &desc_size, &avail_size, &used_size);
        uint64_t all_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE) + PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        queue->inner.legacy = malloc(sizeof(virtqueue_legacy_t));
        queue->inner.legacy->paddr = translate_address(get_current_page_dir(false), alloc_frames_bytes(all_size));
        queue->inner.legacy->size = all_size;
        queue->inner.legacy->avail_offset = desc_size;
        queue->inner.legacy->used_offset = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);

        // TODO
        // driver->op->queue_set(driver->data, queue_idx, QUEUE_SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);
    }
    else
    {
        queue->is_modern = true;
        uint64_t desc_size, avail_size, used_size;
        queue_part_sizes(QUEUE_SIZE, &desc_size, &avail_size, &used_size);
        queue->inner.modern = malloc(sizeof(virtqueue_modern_t));
        queue->inner.modern->driver_to_device_paddr = translate_address(get_current_page_dir(false), alloc_frames_bytes(PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->driver_to_device_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->device_to_driver_paddr = translate_address(get_current_page_dir(false), alloc_frames_bytes(PADDING_UP(used_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->device_to_driver_size = PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->avail_offset = desc_size;

        driver->op->queue_set(driver->data, queue_idx, QUEUE_SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);
    }

    // TODO

    return queue;
}
