#include "queue.h"

void queue_part_sizes(uint16_t queue_size, uint64_t *desc_size, uint64_t *avail_size, uint64_t *used_size)
{
    *desc_size = queue_size * sizeof(virtio_descriptor_t);
    *avail_size = sizeof(uint16_t) * (3 + queue_size);
    *used_size = sizeof(uint16_t) * 3 + sizeof(virtio_used_elem_t) * queue_size;
}

#define QUEUE_SIZE RING_SIZE

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
        // queue_part_sizes(QUEUE_SIZE, &desc_size, &avail_size, &used_size);
        // uint64_t all_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE) + PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        // queue->inner.legacy = malloc(sizeof(virtqueue_legacy_t));
        // queue->inner.legacy->paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(all_size));
        // queue->inner.legacy->size = all_size;
        // queue->inner.legacy->avail_offset = desc_size;
        // queue->inner.legacy->used_offset = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);

        // driver->op->queue_set(driver->data, queue_idx, QUEUE_SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);
    }
    else
    {
        queue->is_modern = true;
        uint64_t desc_size, avail_size, used_size;
        queue_part_sizes(QUEUE_SIZE, &desc_size, &avail_size, &used_size);
        queue->inner.modern = malloc(sizeof(virtqueue_modern_t));
        memset(queue->inner.modern, 0, sizeof(virtqueue_modern_t));
        queue->inner.modern->driver_to_device_paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->driver_to_device_size = PADDING_UP(desc_size + avail_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->device_to_driver_paddr = translate_address(get_current_page_dir(false), (uint64_t)alloc_frames_bytes(PADDING_UP(used_size, DEFAULT_PAGE_SIZE)));
        queue->inner.modern->device_to_driver_size = PADDING_UP(used_size, DEFAULT_PAGE_SIZE);
        queue->inner.modern->avail_offset = desc_size;

        driver->op->queue_set(driver->data, queue_idx, QUEUE_SIZE, queue->inner.modern->driver_to_device_paddr, queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset, queue->inner.modern->device_to_driver_paddr);

        desc = phys_to_virt((virtio_descriptor_t *)queue->inner.modern->driver_to_device_paddr);
        avail = phys_to_virt((virtio_avail_ring_t *)(queue->inner.modern->driver_to_device_paddr + queue->inner.modern->avail_offset));
        used = phys_to_virt((virtio_used_ring_t *)(queue->inner.modern->device_to_driver_paddr));
    }

    queue->desc = desc;
    queue->avail = avail;
    queue->used = used;

    for (int i = 0; i < RING_SIZE - 1; i++)
    {
        queue->desc_shadow[i].next = i + 1;
        desc[i].next = i + 1;
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

uint16_t virt_queue_add(virtqueue_t *queue, virtio_buffer_t *input, virtio_buffer_t *output)
{
    if (!input && !output)
        return (uint16_t)-1;

    uint32_t descriptor_need = input->size / sizeof(virtio_buffer_t) + output->size / sizeof(virtio_buffer_t);

    if (queue->num_used + descriptor_need > QUEUE_SIZE)
    {
        return (uint16_t)-1;
    }

    uint16_t head = queue->free_head;
    uint16_t last = queue->free_head;

    virtio_buffer_t *input_buf = (virtio_buffer_t *)input->addr;
    virtio_buffer_t *output_buf = (virtio_buffer_t *)input->addr;

    for (int i = 0; i < descriptor_need; i++)
    {
        virtio_descriptor_t *desc = &queue->desc_shadow[queue->free_head];

        virtio_buffer_t *buf = (i < (input->size / sizeof(virtio_buffer_t))) ? input_buf + i : output_buf + i - (input->size / sizeof(virtio_buffer_t));

        virtio_descriptor_set_buf(desc, (void *)buf->addr, buf->size, (i < (input->size / sizeof(virtio_buffer_t))) ? VIRTIO_DESC_BUFFER_DIR_DRIVER_TO_DEVICE : VIRTIO_DESC_BUFFER_DIR_DEVICE_TO_DRIVER, DESC_FLAGS_NEXT);

        last = queue->free_head;
        queue->free_head = desc->next;

        memcpy(&queue->desc[last], &queue->desc_shadow[last], sizeof(virtio_descriptor_t));
    }

    queue->desc_shadow[last].flags &= (~DESC_FLAGS_NEXT);
    memcpy(&queue->desc[last], &queue->desc_shadow[last], sizeof(virtio_descriptor_t));

    queue->num_used += descriptor_need;

    return head;
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

void virt_queue_recycle_descriptors(virtqueue_t *queue, uint32_t head, virtio_buffer_t *input, virtio_buffer_t *output)
{
    uint16_t original_free_head = queue->free_head;
    queue->free_head = head;

    virtio_descriptor_t *head_desc = &queue->desc_shadow[head];
    if (head_desc->flags & DESC_FLAGS_INDIRECT)
    {
        // TODO
    }
    else
    {
        uint16_t next = head;

        uint32_t descriptor_need = input->size / sizeof(virtio_buffer_t) + output->size / sizeof(virtio_buffer_t);

        virtio_buffer_t *input_buf = (virtio_buffer_t *)input->addr;
        virtio_buffer_t *output_buf = (virtio_buffer_t *)input->addr;

        for (int i = 0; i < descriptor_need; i++)
        {
            uint16_t desc_index = next;
            virtio_descriptor_t *desc = &queue->desc_shadow[head];

            uint64_t paddr = desc->addr;
            desc->addr = 0;
            desc->len = 0;
            queue->num_used--;
            next = desc->next;
            if (!next)
            {
                desc->next = original_free_head;
            }

            memcpy(&queue->desc[desc_index], &queue->desc_shadow[desc_index], sizeof(virtio_descriptor_t));
        }
    }
}

uint32_t virt_queue_pop_used(virtqueue_t *queue, uint16_t token, virtio_buffer_t *input, virtio_buffer_t *output)
{
    if (!virt_queue_can_pop(queue))
        return 0;

    uint16_t last_used_slot = queue->last_used_idx & (QUEUE_SIZE - 1);
    uint16_t index = queue->used->ring[last_used_slot].id;
    uint32_t len = queue->used->ring[last_used_slot].len;

    if (index != token)
        return (uint32_t)-1;

    // recycle_descriptors
    virt_queue_recycle_descriptors(queue, index, input, output);

    queue->last_used_idx++;

    if (queue->event_idx)
    {
        queue->avail->used_event = queue->last_used_idx;
    }

    return len;
}
