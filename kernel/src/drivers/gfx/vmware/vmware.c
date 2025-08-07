#include <arch/arch.h>
#include <drivers/bus/pci.h>
#include <drivers/gfx/vmware/vmware.h>

#if defined(__x86_64__)

static pci_device_t *devices[MAX_VMWARE_GPU_DEVICE_NUM];
static uint32_t devices_count = 0;

vmware_gpu_device_t *vmware_gpu_devices[MAX_VMWARE_GPU_DEVICE_NUM];
uint32_t vmware_gpu_devices_count = 0;

static spinlock_t register_rw_lock = {0};

static uint32_t read_register(vmware_gpu_device_t *device, uint32_t index)
{
    spin_lock(&register_rw_lock);
    io_out32(device->io_base + 0x00, index);
    uint32_t ret = io_in32(device->io_base + 0x01);
    spin_unlock(&register_rw_lock);
    return ret;
}

static void write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    spin_lock(&register_rw_lock);
    io_out32(device->io_base + 0x00, index);
    io_out32(device->io_base + 0x01, value);
    spin_unlock(&register_rw_lock);
}

static uint32_t fifo_read_register(vmware_gpu_device_t *device, uint32_t index)
{
    return ((uint32_t *)device->fifo_mmio_base)[index];
}

static void fifo_write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    ((uint32_t *)device->fifo_mmio_base)[index] = value;
}

static inline bool has_capability(vmware_gpu_device_t *device, enum caps capability)
{
    return (device->caps & (uint32_t)capability) != 0;
}

void vmware_gpu_pci_init(pci_device_t *device)
{
    vmware_gpu_devices[vmware_gpu_devices_count] = malloc(sizeof(vmware_gpu_device_t));
    vmware_gpu_devices[vmware_gpu_devices_count]->io_base = device->bars[0].address;
    vmware_gpu_devices[vmware_gpu_devices_count]->fb_mmio_base = phys_to_virt((uint64_t)device->bars[1].address);
    vmware_gpu_devices[vmware_gpu_devices_count]->fifo_mmio_base = phys_to_virt((uint64_t)device->bars[2].address);

    map_page_range(get_current_page_dir(false), vmware_gpu_devices[vmware_gpu_devices_count]->fb_mmio_base, device->bars[1].address, device->bars[1].size, PT_FLAG_R | PT_FLAG_W);
    map_page_range(get_current_page_dir(false), vmware_gpu_devices[vmware_gpu_devices_count]->fifo_mmio_base, device->bars[2].address, device->bars[2].size, PT_FLAG_R | PT_FLAG_W);

    uint32_t _deviceVersion = VMWARE_GPU_VERSION_ID_2;

    do
    {
        write_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_id, _deviceVersion);
        if (read_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_id) == _deviceVersion)
        {
            break;
        }

        _deviceVersion--;
    } while (_deviceVersion >= VMWARE_GPU_VERSION_ID_0);

    vmware_gpu_devices[vmware_gpu_devices_count]->version = _deviceVersion;

    uint32_t fifosize = read_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_mem_size);

    vmware_gpu_devices[vmware_gpu_devices_count]->fifo_size = fifosize;

    vmware_gpu_devices[vmware_gpu_devices_count]->caps = _deviceVersion >= VMWARE_GPU_VERSION_ID_1 ? read_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_capabilities) : 0;

    uint32_t min = fifo_index_num_regs * 4;
    fifo_write_register(vmware_gpu_devices[vmware_gpu_devices_count], fifo_index_min, min);
    fifo_write_register(vmware_gpu_devices[vmware_gpu_devices_count], fifo_index_max, fifosize);
    fifo_write_register(vmware_gpu_devices[vmware_gpu_devices_count], fifo_index_next_cmd, min);
    fifo_write_register(vmware_gpu_devices[vmware_gpu_devices_count], fifo_index_stop, min);

    // write_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_config_done, 1);

    if (vmware_gpu_devices[vmware_gpu_devices_count]->caps & (uint32_t)cap_irqmask)
    {
        write_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_irqmask, 0);
        io_out32(vmware_gpu_devices[vmware_gpu_devices_count]->io_base + 0x08, 0xFF);
    }
    else
    {
        printk("gfx/vmware: device doesn't support interrupts\n");
    }

    uint32_t current_w = read_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_width);
    uint32_t current_h = read_register(vmware_gpu_devices[vmware_gpu_devices_count], register_index_height);

    vmware_gpu_devices[vmware_gpu_devices_count]->current_w = current_w;
    vmware_gpu_devices[vmware_gpu_devices_count]->current_h = current_h;

    vmware_gpu_devices_count++;
}

void vmware_gpu_init()
{
    pci_device_t *pci_devices[MAX_VMWARE_GPU_DEVICE_NUM];
    uint32_t count = 0;
    pci_find_vid(pci_devices, &count, 0x15ad);

    for (uint32_t i = 0; i < count; i++)
    {
        if (pci_devices[i]->device_id == 0x0405)
        {
            devices[devices_count++] = pci_devices[i];
        }
    }

    for (uint32_t i = 0; i < devices_count; i++)
    {
        pci_device_t *dev = devices[i];
        vmware_gpu_pci_init(dev);
    }
}

static void wait_irq(vmware_gpu_device_t *gpu, uint32_t irq_mask)
{
    static uint64_t irq_sequence;

    if (gpu->caps & (uint32_t)cap_irqmask)
    {
        write_register(gpu, register_index_irqmask, irq_mask);
        write_register(gpu, register_index_sync, 1);

        while (true)
        {
            uint32_t irq_flags = io_in32(gpu->io_base + 0x08);
            if (!(irq_flags & irq_mask))
            {
                continue;
            }

            io_out32(gpu->io_base + 0x08, irq_flags);

            break;
        }
    }
    else
    {
        write_register(gpu, register_index_sync, 1);
        read_register(gpu, register_index_busy);
    }
}

uint8_t bounce_buf[1024 * 1024];
bool _usingBounceBuf;

static inline void *reserve(vmware_gpu_device_t *dev, size_t size)
{
    size_t bytes = size * 4;
    uint32_t min = fifo_read_register(dev, fifo_index_min);
    uint32_t max = fifo_read_register(dev, fifo_index_max);
    uint32_t next_cmd = fifo_read_register(dev, fifo_index_next_cmd);

    bool reserveable = has_capability(dev, cap_fifo_reserve);

    while (1)
    {
        uint32_t stop = fifo_read_register(dev, fifo_index_stop);
        bool in_place = false;

        if (next_cmd >= stop)
        {
            if (next_cmd + bytes < max ||
                (next_cmd + bytes == max && stop > min))
                in_place = true;

            else if ((max - next_cmd) + (stop - min) <= bytes)
            {
                wait_irq(dev, 2); // TODO: add a definiton for the mask
            }
            else
            {
                _usingBounceBuf = true;
            }
        }
        else
        {
            if (next_cmd + bytes < stop)
                in_place = true;
            else
                wait_irq(dev, 2); // TODO: add a definiton for the mask
        }

        if (in_place)
        {
            if (reserveable)
            {
                fifo_write_register(dev, fifo_index_reserved, bytes);
                uint64_t mem = dev->fifo_mmio_base;
                void *ptr = (void *)(mem + next_cmd);

                return ptr;
            }
        }

        return bounce_buf;
    }

    return NULL;
}

static inline void commit(vmware_gpu_device_t *dev, size_t bytes)
{
    uint32_t min = fifo_read_register(dev, fifo_index_min);
    uint32_t max = fifo_read_register(dev, fifo_index_max);
    uint32_t next_cmd = fifo_read_register(dev, fifo_index_next_cmd);

    bool reserveable = has_capability(dev, cap_fifo_reserve);

    if (_usingBounceBuf)
    {
        if (reserveable)
        {
            uint8_t *fifo = (uint8_t *)dev->fifo_mmio_base;

            size_t chunk_size = MIN(bytes, (size_t)(max - next_cmd));
            fifo_write_register(dev, fifo_index_reserved, bytes);
            memcpy(fifo + next_cmd, bounce_buf, chunk_size);
            memcpy(fifo + min, &bounce_buf[chunk_size], bytes - chunk_size);
        }
        else
        {
            uint32_t *buf = (uint32_t *)bounce_buf;
            uint32_t *fifo = (uint32_t *)dev->fifo_mmio_base;
            while (bytes)
            {
                fifo[next_cmd / 4] = *buf++;
                next_cmd += 4;
                if (next_cmd >= max)
                {
                    next_cmd -= max - min;
                }
                fifo_write_register(dev, fifo_index_next_cmd, next_cmd);
                bytes -= 4;
            }
        }
    }
    else
    {
        next_cmd += bytes;
        if (next_cmd >= max)
            next_cmd -= max - min;

        fifo_write_register(dev, fifo_index_next_cmd, next_cmd);
    }

    if (reserveable)
        fifo_write_register(dev, fifo_index_reserved, 0);
}

// About DRM

int vmware_get_display_info(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp)
{
    vmware_gpu_device_t *dev = dev_data;
    *width = dev->current_w;
    *height = dev->current_h;
    *bpp = 32; // todo

    return 0;
}

int vmware_set_plane(void *dev_data, struct drm_mode_set_plane *plane)
{
    return 0;
}

int vmware_set_crtc(void *dev_data, struct drm_mode_crtc *crtc)
{
    return 0;
}

int vmware_set_cursor(void *dev_data, struct drm_mode_cursor *cursor)
{
    return 0;
}

int vmware_create_dumb(void *dev_data, struct drm_mode_create_dumb *args)
{
    vmware_gpu_device_t *dev = dev_data;

    args->pitch = args->width * args->bpp / 8;
    uint64_t size = args->height * args->pitch;
    args->size = size;

    vmware_gpu_fb_t *fb = malloc(sizeof(vmware_gpu_fb_t));
    fb->addr = alloc_frames((size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
    fb->width = args->width;
    fb->height = args->height;

    int i = -1;
    for (i = 0; i < MAX_FB_NUM; i++)
    {
        if (!dev->fbs[i])
        {
            dev->fbs[i] = fb;
            break;
        }
    }

    args->handle = i;

    return 0;
}

int vmware_map_dumb(void *dev_data, struct drm_mode_map_dumb *args)
{
    vmware_gpu_device_t *dev = dev_data;

    vmware_gpu_fb_t *fb = dev->fbs[args->handle];

    args->offset = fb->addr;

    return 0;
}

static int vmware_get_fb(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp, uint64_t *addr)
{
    vmware_gpu_device_t *gpu = dev_data;

    size_t cols, rows;
    os_terminal_get_screen_info((size_t *)addr, (size_t *)width, (size_t *)height, (size_t *)bpp, &cols, &rows);

    return 0;
}

int vmware_add_fb(void *dev_data, struct drm_mode_fb_cmd *cmd)
{
    vmware_gpu_device_t *dev = dev_data;

    return 0;
}

int vmware_page_flip(drm_device_t *dev, struct drm_mode_crtc_page_flip *flip)
{
    if (flip->crtc_id != 1)
        return -ENOENT;

    vmware_gpu_device_t *gpu = dev->data;

    size_t cmd_size = sizeof(struct vmware_gpu_update_rectangle) / 4 + 1;

    vmware_gpu_fb_t *fb = gpu->fbs[flip->fb_id];

    fast_copy_16((void *)gpu->fb_mmio_base, (const void *)phys_to_virt(fb->addr), fb->width * fb->height * 4);

    uint32_t *ptr = reserve(gpu, cmd_size);
    ptr[0] = command_index_update;
    struct vmware_gpu_update_rectangle *cmd = (struct vmware_gpu_update_rectangle *)(&ptr[1]);
    cmd->x = 0;
    cmd->y = 0;
    cmd->w = fb->width;
    cmd->h = fb->height;

    commit(gpu, cmd_size * 4);

    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++)
    {
        if (!dev->drm_events[i])
        {
            dev->drm_events[i] = malloc(sizeof(struct k_drm_event));
            dev->drm_events[i]->type = DRM_EVENT_FLIP_COMPLETE;
            dev->drm_events[i]->user_data = flip->user_data;
            dev->drm_events[i]->timestamp.tv_sec = nanoTime() / 1000000000ULL;
            dev->drm_events[i]->timestamp.tv_nsec = nanoTime() % 1000000000ULL;
            break;
        }
    }

    return 0;
}

drm_device_op_t vmware_drm_device_op = {
    .get_display_info = vmware_get_display_info,
    .set_crtc = vmware_set_crtc,
    .set_cursor = vmware_set_cursor,
    .set_plane = vmware_set_plane,
    .create_dumb = vmware_create_dumb,
    .map_dumb = vmware_map_dumb,
    .get_fb = vmware_get_fb,
    .add_fb = vmware_add_fb,
    .page_flip = vmware_page_flip,
};

#endif
