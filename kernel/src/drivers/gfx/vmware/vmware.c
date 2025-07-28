#include <arch/arch.h>
#include <drivers/bus/pci.h>
#include <drivers/gfx/vmware/vmware.h>

#if defined(__x86_64__)

pci_device_t *devices[MAX_VMWARE_GPU_DEVICE_NUM];
uint32_t devices_count = 0;

static vmware_gpu_device_t *gpu_devices[MAX_VMWARE_GPU_DEVICE_NUM];
static uint32_t gpu_devices_count = 0;

static uint32_t read_register(vmware_gpu_device_t *device, uint32_t index)
{
    io_out32(device->io_base + 0x00, index);
    return io_in32(device->io_base + 0x01);
}

static void write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    io_out32(device->io_base + 0x00, index);
    io_out32(device->io_base + 0x01, value);
}

static uint32_t fifo_read_register(vmware_gpu_device_t *device, uint32_t index)
{
    return ((uint32_t *)device->fifo_mmio_base)[index];
}

static void fifo_write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value)
{
    ((uint32_t *)device->fifo_mmio_base)[index] = value;
}

void vmware_gpu_pci_init(pci_device_t *device)
{
    gpu_devices[gpu_devices_count] = malloc(sizeof(vmware_gpu_device_t));
    gpu_devices[gpu_devices_count]->io_base = device->bars[0].address;
    gpu_devices[gpu_devices_count]->fb_mmio_base = phys_to_virt((uint64_t)device->bars[1].address);
    gpu_devices[gpu_devices_count]->fifo_mmio_base = phys_to_virt((uint64_t)device->bars[2].address);

    map_page_range(get_current_page_dir(false), gpu_devices[gpu_devices_count]->fb_mmio_base, device->bars[1].address, device->bars[1].size, PT_FLAG_R | PT_FLAG_W);
    map_page_range(get_current_page_dir(false), gpu_devices[gpu_devices_count]->fifo_mmio_base, device->bars[2].address, device->bars[2].size, PT_FLAG_R | PT_FLAG_W);

    uint32_t _deviceVersion = VMWARE_GPU_VERSION_ID_2;

    do
    {
        write_register(gpu_devices[gpu_devices_count], register_index_id, _deviceVersion);
        if (read_register(gpu_devices[gpu_devices_count], register_index_id) == _deviceVersion)
        {
            break;
        }

        _deviceVersion--;
    } while (_deviceVersion >= VMWARE_GPU_VERSION_ID_0);

    gpu_devices[gpu_devices_count]->version = _deviceVersion;

    uint32_t fifosize = read_register(gpu_devices[gpu_devices_count], register_index_mem_size);

    gpu_devices[gpu_devices_count]->fifosize = fifosize;

    uint32_t min = fifo_index_num_regs * 4;
    fifo_write_register(gpu_devices[gpu_devices_count], fifo_index_min, min);
    fifo_write_register(gpu_devices[gpu_devices_count], fifo_index_max, fifosize);
    fifo_write_register(gpu_devices[gpu_devices_count], fifo_index_next_cmd, min);
    fifo_write_register(gpu_devices[gpu_devices_count], fifo_index_stop, min);

    write_register(gpu_devices[gpu_devices_count], register_index_config_done, 1);

    uint32_t current_w = read_register(gpu_devices[gpu_devices_count], register_index_width);
    uint32_t current_h = read_register(gpu_devices[gpu_devices_count], register_index_height);

    gpu_devices[gpu_devices_count]->current_w = current_w;
    gpu_devices[gpu_devices_count]->current_h = current_h;

    gpu_devices_count++;
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

drm_device_op_t vmware_drm_device_op = {
    .get_display_info = vmware_get_display_info,
    .set_crtc = vmware_set_crtc,
    .set_cursor = vmware_set_cursor,
    .set_plane = vmware_set_plane,
};

#endif
