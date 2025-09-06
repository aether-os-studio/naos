#include <arch/arch.h>
#include <drivers/bus/pci.h>
#include <drivers/fb.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm.h>
#include <drivers/drm/drm_fourcc.h>
#include <drivers/gfx/vmware/vmware.h>
#include <mm/mm.h>

#if defined(__x86_64__)

vmware_gpu_device_t *vmware_gpu_devices[MAX_VMWARE_GPU_DEVICES];
uint32_t vmware_gpu_devices_count = 0;

// Synchronization
static spinlock_t register_lock = {0};

// Utility functions
static inline uint32_t vmware_read_register(vmware_gpu_device_t *device, uint32_t index)
{
    spin_lock(&register_lock);
    io_out32(device->io_base + 0x00, index);
    uint32_t ret = io_in32(device->io_base + 0x01);
    spin_unlock(&register_lock);
    return ret;
}

static inline void vmware_write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    spin_lock(&register_lock);
    io_out32(device->io_base + 0x00, index);
    io_out32(device->io_base + 0x01, value);
    spin_unlock(&register_lock);
}

static inline uint32_t vmware_fifo_read(vmware_gpu_device_t *device, uint32_t index)
{
    return ((uint32_t *)device->fifo_mmio_base)[index];
}

static inline void vmware_fifo_write(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    ((uint32_t *)device->fifo_mmio_base)[index] = value;
}

static inline bool vmware_has_capability(vmware_gpu_device_t *device, enum caps capability)
{
    return (device->caps & (uint32_t)capability) != 0;
}

// FIFO management
static uint8_t bounce_buffer[1024 * 1024];
static bool using_bounce_buffer = false;

void *vmware_fifo_reserve(vmware_gpu_device_t *device, size_t size)
{
    size_t bytes = size * 4;
    uint32_t min = vmware_fifo_read(device, fifo_index_min);
    uint32_t max = vmware_fifo_read(device, fifo_index_max);
    uint32_t next_cmd = vmware_fifo_read(device, fifo_index_next_cmd);
    uint32_t stop = vmware_fifo_read(device, fifo_index_stop);

    bool reserveable = vmware_has_capability(device, cap_fifo_reserve);

    // Check if we can fit in place
    if (next_cmd >= stop)
    {
        if (next_cmd + bytes < max || (next_cmd + bytes == max && stop > min))
        {
            // Fits at the end
            if (reserveable)
            {
                vmware_fifo_write(device, fifo_index_reserved, bytes);
                return (void *)(device->fifo_mmio_base + next_cmd);
            }
        }
        else if ((max - next_cmd) + (stop - min) >= bytes)
        {
            // Wraps around and fits
            using_bounce_buffer = true;
        }
        else
        {
            // Need to wait for space
            vmware_write_register(device, register_index_sync, 1);
            while (vmware_read_register(device, register_index_busy))
                ;
            return vmware_fifo_reserve(device, size);
        }
    }
    else
    {
        if (next_cmd + bytes < stop)
        {
            // Fits in current segment
            if (reserveable)
            {
                vmware_fifo_write(device, fifo_index_reserved, bytes);
                return (void *)(device->fifo_mmio_base + next_cmd);
            }
        }
        else
        {
            // Need to wait
            vmware_write_register(device, register_index_sync, 1);
            while (vmware_read_register(device, register_index_busy))
                ;
            return vmware_fifo_reserve(device, size);
        }
    }

    // Use bounce buffer if we can't reserve directly
    using_bounce_buffer = true;
    return bounce_buffer;
}

void vmware_fifo_commit(vmware_gpu_device_t *device, size_t bytes)
{
    uint32_t min = vmware_fifo_read(device, fifo_index_min);
    uint32_t max = vmware_fifo_read(device, fifo_index_max);
    uint32_t next_cmd = vmware_fifo_read(device, fifo_index_next_cmd);
    bool reserveable = vmware_has_capability(device, cap_fifo_reserve);

    if (using_bounce_buffer)
    {
        if (reserveable)
        {
            uint8_t *fifo = (uint8_t *)device->fifo_mmio_base;
            size_t chunk = MIN(bytes, max - next_cmd);
            memcpy(fifo + next_cmd, bounce_buffer, chunk);
            if (bytes > chunk)
            {
                memcpy(fifo + min, bounce_buffer + chunk, bytes - chunk);
            }
            next_cmd = (next_cmd + bytes) % (max - min);
        }
        else
        {
            uint32_t *buf = (uint32_t *)bounce_buffer;
            for (size_t i = 0; i < bytes / 4; i++)
            {
                vmware_fifo_write(device, fifo_index_next_cmd / 4 + i, buf[i]);
            }
        }
        using_bounce_buffer = false;
    }
    else
    {
        next_cmd += bytes;
        if (next_cmd >= max)
        {
            next_cmd = min + (next_cmd - max);
        }
    }

    vmware_fifo_write(device, fifo_index_next_cmd, next_cmd);
    if (reserveable)
    {
        vmware_fifo_write(device, fifo_index_reserved, 0);
    }
}

int vmware_wait_fence(vmware_gpu_device_t *device, uint32_t sequence)
{
    if (vmware_has_capability(device, cap_irqmask))
    {
        // Use interrupt-based waiting
        vmware_write_register(device, register_index_irqmask, irq_mask_fence);
        vmware_fifo_write(device, fifo_index_fence_goal, sequence);

        // Wait for interrupt
        while (!(device->pending_irqs & irq_mask_fence))
        {
            arch_yield();
        }
        device->pending_irqs &= ~irq_mask_fence;
    }
    else
    {
        // Polling fallback
        while (vmware_fifo_read(device, fifo_index_fence) < sequence)
        {
            arch_yield();
        }
    }
    return 0;
}

// Display detection and management
int vmware_gpu_detect_displays(vmware_gpu_device_t *device)
{
    uint32_t num_displays = vmware_read_register(device, register_index_num_displays);
    device->num_displays = MIN(num_displays, VMWARE_MAX_DISPLAYS);

    for (uint32_t i = 0; i < device->num_displays; i++)
    {
        vmware_display_info_t *display = &device->displays[i];

        vmware_write_register(device, register_index_display_id, i);
        display->id = i;
        display->is_primary = vmware_read_register(device, register_index_display_is_primary);
        display->position_x = vmware_read_register(device, register_index_display_position_x);
        display->position_y = vmware_read_register(device, register_index_display_position_y);
        display->width = vmware_read_register(device, register_index_display_width);
        display->height = vmware_read_register(device, register_index_display_height);
        display->enabled = display->width > 0 && display->height > 0;
    }

    return device->num_displays;
}

int vmware_gpu_set_display_mode(vmware_gpu_device_t *device, uint32_t display_id,
                                uint32_t width, uint32_t height, uint32_t bpp)
{
    if (display_id >= device->num_displays)
    {
        return -EINVAL;
    }

    vmware_write_register(device, register_index_display_id, display_id);
    vmware_write_register(device, register_index_width, width);
    vmware_write_register(device, register_index_height, height);
    vmware_write_register(device, register_index_bits_per_pixel, bpp);
    vmware_write_register(device, register_index_config_done, 1);

    device->displays[display_id].width = width;
    device->displays[display_id].height = height;
    device->displays[display_id].enabled = true;

    return 0;
}

int vmware_gpu_update_display(vmware_gpu_device_t *device, uint32_t display_id,
                              uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (display_id >= device->num_displays || !device->displays[display_id].enabled)
    {
        return -EINVAL;
    }

    size_t cmd_size = sizeof(struct vmware_gpu_update_rectangle) / 4 + 1;
    uint32_t *ptr = vmware_fifo_reserve(device, cmd_size);

    ptr[0] = command_index_update;
    struct vmware_gpu_update_rectangle *cmd = (struct vmware_gpu_update_rectangle *)(&ptr[1]);
    cmd->x = x;
    cmd->y = y;
    cmd->w = w;
    cmd->h = h;

    vmware_fifo_commit(device, cmd_size * 4);

    return 0;
}

// Cursor management
int vmware_gpu_set_cursor(vmware_gpu_device_t *device, uint32_t display_id,
                          vmware_cursor_t *cursor, uint32_t x, uint32_t y)
{
    if (!vmware_has_capability(device, cap_cursor))
    {
        return -ENOTSUP;
    }

    if (device->cursor)
    {
        device->cursor->refcount--;
        if (device->cursor->refcount == 0)
        {
            free(device->cursor->pixels);
            free(device->cursor);
        }
    }

    device->cursor = cursor;
    device->cursor->refcount++;

    // Define cursor command
    size_t cmd_size = (sizeof(struct vmware_gpu_define_alpha_cursor) +
                       cursor->width * cursor->height * 4) /
                          4 +
                      1;
    uint32_t *ptr = vmware_fifo_reserve(device, cmd_size);

    ptr[0] = command_index_define_alpha_cursor;
    struct vmware_gpu_define_alpha_cursor *cmd = (struct vmware_gpu_define_alpha_cursor *)(&ptr[1]);
    cmd->id = 0;
    cmd->hotspot_x = cursor->hotspot_x;
    cmd->hotspot_y = cursor->hotspot_y;
    cmd->width = cursor->width;
    cmd->height = cursor->height;
    memcpy(cmd->pixel_data, cursor->pixels, cursor->width * cursor->height * 4);

    vmware_fifo_commit(device, cmd_size * 4);

    // Move cursor to position
    return vmware_gpu_move_cursor(device, display_id, x, y);
}

int vmware_gpu_move_cursor(vmware_gpu_device_t *device, uint32_t display_id,
                           uint32_t x, uint32_t y)
{
    if (!vmware_has_capability(device, cap_cursor))
    {
        return -ENOTSUP;
    }

    vmware_write_register(device, register_index_cursor_id, 0);
    vmware_write_register(device, register_index_cursor_x, x);
    vmware_write_register(device, register_index_cursor_y, y);
    vmware_write_register(device, register_index_cursor_on, 1);

    return 0;
}

// PCI initialization
void vmware_gpu_pci_init(pci_device_t *pci_dev)
{
    vmware_gpu_device_t *device = malloc(sizeof(vmware_gpu_device_t));
    memset(device, 0, sizeof(vmware_gpu_device_t));

    device->io_base = pci_dev->bars[0].address;
    device->fb_mmio_base = phys_to_virt((uint64_t)pci_dev->bars[1].address);
    device->fifo_mmio_base = phys_to_virt((uint64_t)pci_dev->bars[2].address);

    // Map MMIO regions
    map_page_range(get_current_page_dir(false), device->fb_mmio_base,
                   pci_dev->bars[1].address, pci_dev->bars[1].size, PT_FLAG_R | PT_FLAG_W);
    map_page_range(get_current_page_dir(false), device->fifo_mmio_base,
                   pci_dev->bars[2].address, pci_dev->bars[2].size, PT_FLAG_R | PT_FLAG_W);

    // Detect device version
    uint32_t device_version = VMWARE_GPU_VERSION_ID_2;
    do
    {
        vmware_write_register(device, register_index_id, device_version);
        if (vmware_read_register(device, register_index_id) == device_version)
        {
            break;
        }
        device_version--;
    } while (device_version >= VMWARE_GPU_VERSION_ID_0);

    device->version = device_version;

    // Read capabilities and sizes
    device->fifo_size = vmware_read_register(device, register_index_mem_size);
    device->vram_size = vmware_read_register(device, register_index_vram_size);
    device->caps = device_version >= VMWARE_GPU_VERSION_ID_1 ? vmware_read_register(device, register_index_capabilities) : 0;

    // Initialize FIFO
    uint32_t min = fifo_index_num_regs * 4;
    vmware_fifo_write(device, fifo_index_min, min);
    vmware_fifo_write(device, fifo_index_max, device->fifo_size);
    vmware_fifo_write(device, fifo_index_next_cmd, min);
    vmware_fifo_write(device, fifo_index_stop, min);

    // Setup interrupts if supported
    if (vmware_has_capability(device, cap_irqmask))
    {
        vmware_write_register(device, register_index_irqmask, 0);
        io_out32(device->io_base + 0x08, 0xFF);
    }

    // Detect displays
    vmware_gpu_detect_displays(device);

    // Initialize DRM resources
    for (uint32_t i = 0; i < device->num_displays; i++)
    {
        if (device->displays[i].enabled)
        {
            // Create connector
            device->connectors[i] = drm_connector_alloc(NULL, DRM_MODE_CONNECTOR_VIRTUAL, device);
            if (device->connectors[i])
            {
                device->connectors[i]->connection = DRM_MODE_CONNECTED;
                device->connectors[i]->mm_width = device->displays[i].width;
                device->connectors[i]->mm_height = device->displays[i].height;
            }

            // Create CRTC
            device->crtcs[i] = drm_crtc_alloc(NULL, device);

            // Create encoder
            device->encoders[i] = drm_encoder_alloc(NULL, DRM_MODE_ENCODER_VIRTUAL, device);
            if (device->encoders[i] && device->connectors[i] && device->crtcs[i])
            {
                device->encoders[i]->possible_crtcs = 1 << i;
                device->connectors[i]->encoder_id = device->encoders[i]->id;
                device->connectors[i]->crtc_id = device->crtcs[i]->id;
            }
        }
    }

    vmware_gpu_devices[vmware_gpu_devices_count++] = device;
}

// DRM device operations
static int vmware_get_display_info(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp)
{
    vmware_gpu_device_t *device = dev_data;
    if (device->num_displays > 0)
    {
        *width = device->displays[0].width;
        *height = device->displays[0].height;
        *bpp = 32; // VMware typically uses 32bpp
        return 0;
    }
    return -ENODEV;
}

static int vmware_get_fb(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp, uint64_t *addr)
{
    vmware_gpu_device_t *device = dev_data;
    *width = device->displays[0].width;
    *height = device->displays[0].height;
    *bpp = 32;
    *addr = device->fb_mmio_base;
    return 0;
}

static int vmware_create_dumb(void *dev_data, struct drm_mode_create_dumb *args)
{
    vmware_gpu_device_t *device = dev_data;

    args->pitch = args->width * (args->bpp / 8);
    args->size = args->height * args->pitch;

    vmware_framebuffer_t *fb = malloc(sizeof(vmware_framebuffer_t));
    if (!fb)
        return -ENOMEM;

    memset(fb, 0, sizeof(vmware_framebuffer_t));
    fb->addr = alloc_frames((args->size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
    fb->width = args->width;
    fb->height = args->height;
    fb->pitch = args->pitch;
    fb->bpp = args->bpp;
    fb->format = DRM_FORMAT_XRGB8888;
    fb->refcount = 1;

    // Find free slot
    for (uint32_t i = 0; i < VMWARE_MAX_FRAMEBUFFERS; i++)
    {
        if (!device->framebuffers[i])
        {
            device->framebuffers[i] = fb;
            args->handle = i;
            return 0;
        }
    }

    free(fb);
    return -ENOSPC;
}

static int vmware_destroy_dumb(void *dev_data, uint32_t handle)
{
    vmware_gpu_device_t *device = dev_data;

    if (handle >= VMWARE_MAX_FRAMEBUFFERS || !device->framebuffers[handle])
    {
        return -EINVAL;
    }

    vmware_framebuffer_t *fb = device->framebuffers[handle];
    if (--fb->refcount == 0)
    {
        free_frames(fb->addr, (fb->pitch * fb->height + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
        free(fb);
    }
    device->framebuffers[handle] = NULL;

    return 0;
}

static int vmware_map_dumb(void *dev_data, struct drm_mode_map_dumb *args)
{
    vmware_gpu_device_t *device = dev_data;

    if (args->handle >= VMWARE_MAX_FRAMEBUFFERS || !device->framebuffers[args->handle])
    {
        return -EINVAL;
    }

    vmware_framebuffer_t *fb = device->framebuffers[args->handle];
    args->offset = fb->addr;

    return 0;
}

static int vmware_page_flip(drm_device_t *drm_dev, struct drm_mode_crtc_page_flip *flip)
{
    vmware_gpu_device_t *device = drm_dev->data;

    if (flip->crtc_id >= device->num_displays || flip->fb_id >= VMWARE_MAX_FRAMEBUFFERS)
    {
        return -EINVAL;
    }

    vmware_framebuffer_t *fb = device->framebuffers[flip->fb_id];
    if (!fb)
        return -EINVAL;

    // Copy framebuffer to display
    fast_copy_16((void *)device->fb_mmio_base, (const void *)phys_to_virt(fb->addr),
                 fb->width * fb->height * 4);

    // Update entire display
    vmware_gpu_update_display(device, flip->crtc_id, 0, 0, fb->width, fb->height);

    // Create flip complete event
    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++)
    {
        if (!drm_dev->drm_events[i])
        {
            drm_dev->drm_events[i] = malloc(sizeof(struct k_drm_event));
            drm_dev->drm_events[i]->type = DRM_EVENT_FLIP_COMPLETE;
            drm_dev->drm_events[i]->user_data = flip->user_data;
            drm_dev->drm_events[i]->timestamp.tv_sec = nanoTime() / 1000000000ULL;
            drm_dev->drm_events[i]->timestamp.tv_nsec = nanoTime() % 1000000000ULL;
            break;
        }
    }

    return 0;
}

static int vmware_set_crtc(void *dev_data, struct drm_mode_crtc *crtc)
{
    // CRTC configuration handled by page flip
    return 0;
}

static int vmware_set_cursor(void *dev_data, struct drm_mode_cursor *cursor)
{
    vmware_gpu_device_t *device = dev_data;

    if (!vmware_has_capability(device, cap_cursor))
    {
        return -ENOTSUP;
    }

    if (cursor->handle == 0)
    {
        // Hide cursor
        vmware_write_register(device, register_index_cursor_on, 0);
        return 0;
    }

    // For simplicity, create a basic cursor
    vmware_cursor_t *vmware_cursor = malloc(sizeof(vmware_cursor_t));
    if (!vmware_cursor)
        return -ENOMEM;

    vmware_cursor->width = VMWARE_CURSOR_WIDTH;
    vmware_cursor->height = VMWARE_CURSOR_HEIGHT;
    vmware_cursor->hotspot_x = 0;
    vmware_cursor->hotspot_y = 0;
    vmware_cursor->pixels = malloc(VMWARE_CURSOR_WIDTH * VMWARE_CURSOR_HEIGHT * 4);
    vmware_cursor->refcount = 1;

    // Create a simple arrow cursor
    memset(vmware_cursor->pixels, 0, VMWARE_CURSOR_WIDTH * VMWARE_CURSOR_HEIGHT * 4);
    // Simple cursor drawing code would go here

    int ret = vmware_gpu_set_cursor(device, cursor->crtc_id, vmware_cursor, cursor->x, cursor->y);
    if (ret != 0)
    {
        free(vmware_cursor->pixels);
        free(vmware_cursor);
    }

    return ret;
}

static int vmware_get_connectors(void *dev_data, drm_connector_t **connectors, uint32_t *count)
{
    vmware_gpu_device_t *device = dev_data;
    *count = 0;

    for (uint32_t i = 0; i < device->num_displays; i++)
    {
        if (device->connectors[i])
        {
            connectors[(*count)++] = device->connectors[i];
        }
    }

    return 0;
}

static int vmware_get_crtcs(void *dev_data, drm_crtc_t **crtcs, uint32_t *count)
{
    vmware_gpu_device_t *device = dev_data;
    *count = 0;

    for (uint32_t i = 0; i < device->num_displays; i++)
    {
        if (device->crtcs[i])
        {
            crtcs[(*count)++] = device->crtcs[i];
        }
    }

    return 0;
}

static int vmware_get_encoders(void *dev_data, drm_encoder_t **encoders, uint32_t *count)
{
    vmware_gpu_device_t *device = dev_data;
    *count = 0;

    for (uint32_t i = 0; i < device->num_displays; i++)
    {
        if (device->encoders[i])
        {
            encoders[(*count)++] = device->encoders[i];
        }
    }

    return 0;
}

static int vmware_get_planes(void *dev_data, drm_plane_t **planes, uint32_t *count)
{
    // VMware doesn't support multiple planes in basic mode
    *count = 0;
    return 0;
}

// DRM device operations structure
drm_device_op_t vmware_drm_device_op = {
    .get_display_info = vmware_get_display_info,
    .get_fb = vmware_get_fb,
    .create_dumb = vmware_create_dumb,
    .destroy_dumb = vmware_destroy_dumb,
    .dirty_fb = NULL,      // Not implemented
    .add_fb = NULL,        // Handled by create_dumb
    .set_plane = NULL,     // Not implemented
    .atomic_commit = NULL, // Not implemented
    .map_dumb = vmware_map_dumb,
    .set_crtc = vmware_set_crtc,
    .page_flip = vmware_page_flip,
    .set_cursor = vmware_set_cursor,
    .gamma_set = NULL, // Not implemented
    .get_connectors = vmware_get_connectors,
    .get_crtcs = vmware_get_crtcs,
    .get_encoders = vmware_get_encoders,
    .get_planes = vmware_get_planes,
};

// Main initialization
void vmware_gpu_init()
{
    pci_device_t *pci_devices[MAX_VMWARE_GPU_DEVICES];
    uint32_t count = 0;
    pci_find_vid(pci_devices, &count, 0x15ad); // VMware vendor ID

    for (uint32_t i = 0; i < count; i++)
    {
        vmware_gpu_pci_init(pci_devices[i]);
    }
}

// IRQ handler
void vmware_gpu_irq_handler(vmware_gpu_device_t *device)
{
    if (!vmware_has_capability(device, cap_irqmask))
    {
        return;
    }

    uint32_t irq_flags = io_in32(device->io_base + 0x08);
    device->pending_irqs |= irq_flags;
    io_out32(device->io_base + 0x08, irq_flags);
}

#endif
