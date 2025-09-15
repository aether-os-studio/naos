#include "queue.h"

void queue_part_sizes(uint16_t queue_size, uint64_t *desc_size, uint64_t *avail_size, uint64_t *used_size)
{
    *desc_size = queue_size * sizeof(virtio_descriptor_t);
    *avail_size = sizeof(uint16_t) * (3 + queue_size);
    *used_size = sizeof(uint16_t) * 3 + sizeof(virtio_used_elem_t) * queue_size;
}

virtqueue_t *virt_queue_new(virtio_driver_t *driver, uint16_t queue_idx, bool indirect, bool event_idx)
{
    if (driver->op->queue_used(driver->data, queue_idx))
        return NULL;

    virtqueue_t *queue = malloc(sizeof(virtqueue_t));
    memset(queue, 0, sizeof(virtqueue_t));

    virtio_descriptor_t *desc = NULL;
    virtio_avail_ring_t *avail = NULL;
    virtio_used_ring_t *used = NULL;

    if (driver->op->requires_legacy_layout(driver->data))
    {
        // TODO

        // queue->is_modern = false;
        // uint64_t desc_size, avail_size, used_size;
        // queue_part_sizes(SIZE, &desc_size, &avail_size, &used_size);
        // uint64_t all_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE) + PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        // queue->inner.legacy = malloc(sizeof(virtqueue_legacy_t));
        // queue->inner.legacy->paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(all_size));
        // queue->inner.legacy->size = all_size;
        // queue->inner.legacy->avail_offset = desc_size;
        // queue->inner.legacy->used_offset = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);

        // driver->op->queue_set(driver->data, queue_idx, SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);
    }
    else
    {
        queue->is_modern = true;
        uint64_t desc_size, avail_size, used_size;
        queue_part_sizes(SIZE, &desc_size, &avail_size, &used_size);
        queue->inner.modern = malloc(sizeof(virtqueue_modern_t));
        memset(queue->inner.modern, 0, sizeof(virtqueue_modern_t));
        queue->inner.modern->driver_to_device_paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->driver_to_device_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->device_to_driver_paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(PADDING_UP(used_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->device_to_driver_size = PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->avail_offset = desc_size;

        driver->op->queue_set(driver->data, queue_idx, SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);

        desc = phys_to_virt((virtio_descriptor_t *)queue->inner.modern->driver_to_device_paddr);
        avail = phys_to_virt((virtio_avail_ring_t *)(queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset));
        used = phys_to_virt((virtio_used_ring_t *)(queue->inner.modern->device_to_driver_paddr));
    }

    queue->desc = desc;
    queue->avail = avail;
    queue->used = used;

    for (int i = 0; i < SIZE; i++)
    {
        if (i < SIZE - 1)
        {
            desc[i].next = i + 1;
        }
        else
        {
            desc[i].next = 0xFFFF;
        }
    }

    queue->queue_idx = queue_idx;

    queue->num_used = 0;
    queue->free_head = 0;

    queue->event_idx = event_idx;

    queue->avail_idx = 0;
    queue->last_used_idx = 0;

    return queue;
}

void virt_queue_set_dev_notify(virtqueue_t *queue, bool enable)
{
    uint16_t avail_ring_flags = enable ? 0x0000 : 0x0001;
    if (!queue->event_idx)
    {
        queue->avail->flags = avail_ring_flags;
    }
}

bool virt_queue_should_notify(virtqueue_t *queue)
{
    if (queue->event_idx)
    {
        uint16_t avail_event = queue->used->avail_event;
        return queue->avail_idx >= avail_event;
    }
    else
    {
        return (queue->used->flags & 0x0001) == 0;
    }
}

bool virt_queue_can_pop(virtqueue_t *queue)
{
    return queue->last_used_idx != queue->used->index;
}

uint16_t virt_queue_get_free_desc(virtqueue_t *queue)
{
    if (queue->free_head == 0xFFFF)
    {
        return 0xFFFF; // No free descriptors
    }

    uint16_t desc_idx = queue->free_head;
    queue->free_head = queue->desc[desc_idx].next;

    return desc_idx;
}

void virt_queue_free_desc(virtqueue_t *queue, uint16_t desc_idx)
{
    uint16_t current_idx = desc_idx;
    uint16_t last_idx = desc_idx;

    // Find the end of the descriptor chain
    while (queue->desc[current_idx].flags & DESC_FLAGS_NEXT)
    {
        last_idx = current_idx;
        current_idx = queue->desc[current_idx].next;
        if (current_idx == 0xFFFF)
            break;
    }

    // Link the last descriptor in the chain to the current free head
    if (current_idx != 0xFFFF)
    {
        queue->desc[current_idx].next = queue->free_head;
        queue->free_head = desc_idx;
    }
    else
    {
        // Chain was broken, just add the original descriptor
        queue->desc[desc_idx].next = queue->free_head;
        queue->free_head = desc_idx;
    }
}

uint16_t virt_queue_add_buf(virtqueue_t *queue, virtio_buffer_t *bufs, uint16_t num_bufs, bool *device_writable)
{
    if (num_bufs == 0 || queue->free_head == 0xFFFF)
    {
        return 0xFFFF;
    }

    uint16_t head_idx = queue->free_head;
    uint16_t current_idx = head_idx;
    uint16_t next_idx;

    // Build the descriptor chain
    for (uint16_t i = 0; i < num_bufs; i++)
    {
        if (current_idx == 0xFFFF)
        {
            // Not enough descriptors, return error
            return 0xFFFF;
        }

        // Get the next free descriptor before we modify current one
        next_idx = queue->desc[current_idx].next;

        // Set up the current descriptor
        virtio_descriptor_set_buf(&queue->desc[current_idx],
                                  (void *)bufs[i].addr,
                                  bufs[i].size,
                                  device_writable[i] ? VIRTIO_DESC_BUFFER_DIR_DEVICE_TO_DRIVER : VIRTIO_DESC_BUFFER_DIR_DRIVER_TO_DEVICE,
                                  i < num_bufs - 1 ? DESC_FLAGS_NEXT : 0);

        // Set the next pointer for chaining (except for the last descriptor)
        if (i < num_bufs - 1)
        {
            queue->desc[current_idx].next = next_idx;
        }
        else
        {
            queue->desc[current_idx].next = 0xFFFF;
        }

        current_idx = next_idx;
    }

    // Update the free head to point to the next available descriptor
    queue->free_head = current_idx;

    return head_idx;
}

void virt_queue_submit_buf(virtqueue_t *queue, uint16_t desc_idx)
{
    queue->avail->ring[queue->avail_idx % SIZE] = desc_idx;
    queue->avail_idx++;
    queue->avail->index = queue->avail_idx;
}

uint16_t virt_queue_get_used_buf(virtqueue_t *queue, uint32_t *len)
{
    if (queue->last_used_idx == queue->used->index)
    {
        return 0xFFFF; // No used buffers
    }

    virtio_used_elem_t *used_elem = &queue->used->ring[queue->last_used_idx % SIZE];
    uint16_t desc_idx = used_elem->id;
    if (len)
    {
        *len = used_elem->len;
    }

    queue->last_used_idx++;
    return desc_idx;
}

void virt_queue_notify(virtio_driver_t *driver, virtqueue_t *queue)
{
    if (virt_queue_should_notify(queue))
    {
        driver->op->notify(driver->data, queue->queue_idx);
    }
}
