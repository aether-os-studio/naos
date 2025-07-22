#include <drivers/bus/pci.h>
#include <drivers/drm/drm.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <mm/mm.h>

#define HZ 60

static uint32_t fb_id_counter = 1;

extern volatile struct limine_framebuffer_request framebuffer_request;

static ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    drm_device_t *dev = (drm_device_t *)data;

    switch (cmd & 0xffffffff)
    {
    case DRM_IOCTL_VERSION:
        *(uint32_t *)arg = 0x010101;
        return 0;

    case DRM_IOCTL_GET_CAP:
    {
        struct drm_get_cap *cap = (struct drm_get_cap *)arg;
        switch (cap->capability)
        {
        case DRM_CAP_DUMB_BUFFER:
            cap->value = 1; // 支持dumb buffer
            return 0;
        default:
            cap->value = 0;
            return 0;
        }
    }

    case DRM_IOCTL_MODE_GETRESOURCES:
    {
        struct drm_mode_card_res *res = (struct drm_mode_card_res *)arg;
        res->count_fbs = 1;
        res->count_crtcs = 1;
        res->count_connectors = 1;
        res->count_encoders = 1;
        res->min_width = dev->framebuffer->width;
        res->min_height = dev->framebuffer->height;
        res->max_width = dev->framebuffer->width;
        res->max_height = dev->framebuffer->height;
        if (res->encoder_id_ptr)
        {
            *(uint32_t *)res->encoder_id_ptr = dev->id;
        }
        if (res->crtc_id_ptr)
        {
            *(uint32_t *)res->crtc_id_ptr = dev->id;
        }
        return 0;
    }

    case DRM_IOCTL_MODE_GETCRTC:
    {
        struct drm_mode_crtc *crtc = (struct drm_mode_crtc *)arg;

        struct drm_mode_modeinfo mode = {
            .clock = dev->framebuffer->width * HZ,
            .hdisplay = dev->framebuffer->width,
            .vdisplay = dev->framebuffer->height,
            .vrefresh = HZ,
        };

        crtc->crtc_id = dev->id;
        crtc->gamma_size = 0;
        crtc->mode_valid = 1;
        memcpy(&crtc->mode, &mode, sizeof(struct drm_mode_modeinfo));
        crtc->fb_id = 1;
        crtc->x = 0;
        crtc->y = 0;
        return 0;
    }

    case DRM_IOCTL_MODE_GETENCODER:
    {
        struct drm_mode_get_encoder *enc = (struct drm_mode_get_encoder *)arg;
        enc->encoder_id = dev->id;
        enc->encoder_type = DRM_MODE_ENCODER_VIRTUAL;
        enc->crtc_id = dev->id;
        enc->possible_crtcs = 1;
        enc->possible_clones = 0;
        return 0;
    }

    case DRM_IOCTL_MODE_CREATE_DUMB:
    {
        struct drm_mode_create_dumb *create = (struct drm_mode_create_dumb *)arg;
        create->height = dev->framebuffer->height;
        create->width = dev->framebuffer->width;
        create->bpp = dev->framebuffer->bpp;
        create->pitch = dev->framebuffer->pitch;
        create->size = create->pitch * create->height;
        create->handle = 1;
        return 0;
    }

    case DRM_IOCTL_MODE_MAP_DUMB:
    {
        struct drm_mode_map_dumb *map = (struct drm_mode_map_dumb *)arg;
        map->offset = translate_address(get_current_page_dir(false), (uint64_t)dev->framebuffer->address);
        return 0;
    }

    case DRM_IOCTL_MODE_DESTROY_DUMB:
    {
        return 0;
    }

    case DRM_IOCTL_MODE_GETCONNECTOR:
    {
        struct drm_mode_get_connector *conn = (struct drm_mode_get_connector *)arg;
        conn->connector_id = 1;
        conn->connection = DRM_MODE_CONNECTOR_VGA;
        conn->count_modes = 1;
        conn->count_props = 0;
        conn->count_encoders = 1;
        struct drm_mode_modeinfo *mode = (struct drm_mode_modeinfo *)(uintptr_t)conn->modes_ptr;
        if (mode)
        {
            sprintf(mode->name, "%dx%d", dev->framebuffer->width, dev->framebuffer->height);
            mode->hdisplay = dev->framebuffer->width;
            mode->vdisplay = dev->framebuffer->height;
            mode->vrefresh = HZ;
            mode->clock = mode->hdisplay * mode->vdisplay * mode->vrefresh / 1000;
            mode->type = DRM_MODE_TYPE_PREFERRED;
        }
        uint32_t *encoders = (uint32_t *)(uintptr_t)conn->encoders_ptr;
        if (encoders)
        {
            encoders[0] = dev->id;
        }
        return 0;
    }
    case DRM_IOCTL_MODE_GETFB:
    {
        struct drm_mode_fb_cmd fb;
        fb.fb_id = fb_id_counter++;
        fb.width = dev->framebuffer->width,
        fb.height = dev->framebuffer->height,
        fb.pitch = dev->framebuffer->pitch,
        fb.bpp = dev->framebuffer->bpp,
        fb.depth = 32,
        fb.handle = (uint32_t)translate_address(get_current_page_dir(false), (uint64_t)dev->framebuffer->address);
        memcpy((void *)arg, &fb, sizeof(fb));
        return 0;
    }
    case DRM_IOCTL_MODE_ADDFB:
    {
        struct drm_mode_fb_cmd *fb = (struct drm_mode_fb_cmd *)arg;

        if (fb->width > dev->framebuffer->width ||
            fb->height > dev->framebuffer->height ||
            fb->bpp != dev->framebuffer->bpp)
        {
            return -EINVAL;
        }

        if (fb->handle != 1)
        {
            return -ENOENT;
        }

        fb->fb_id = fb_id_counter++;

        fb->depth = 32;
        fb->pitch = dev->framebuffer->pitch;

        return 0;
    }
    case DRM_IOCTL_MODE_ADDFB2:
    {
        struct drm_mode_fb_cmd2 *fb = (struct drm_mode_fb_cmd2 *)arg;

        if (fb->width > dev->framebuffer->width || fb->height > dev->framebuffer->height)
        {
            return -EINVAL;
        }

        fb->fb_id = fb_id_counter++;

        fb->handles[0] = 1;
        fb->pitches[0] = dev->framebuffer->pitch;
        fb->offsets[0] = 0;
        fb->modifier[0] = 0;

        return 0;
    }

    case DRM_IOCTL_MODE_SETCRTC:
    {
        struct drm_mode_crtc *crtc = (struct drm_mode_crtc *)arg;

        if (crtc->crtc_id != dev->id)
        {
            return -ENOENT;
        }

        // dev->framebuffer->width = crtc->mode.hdisplay;
        // dev->framebuffer->height = crtc->mode.vdisplay;

        return 0;
    }

    case DRM_IOCTL_MODE_GETPLANERESOURCES:
    {
        struct drm_mode_get_plane_res *res = (struct drm_mode_get_plane_res *)arg;
        res->plane_id_ptr = 0;
        res->count_planes = 0;
        return 0;
    }

    case DRM_IOCTL_MODE_OBJ_GETPROPERTIES:
    {
        struct drm_mode_obj_get_properties *props = (struct drm_mode_obj_get_properties *)arg;
        props->count_props = 0;
        props->props_ptr = 0;
        props->prop_values_ptr = 0;
        return 0;
    }

    case DRM_IOCTL_SET_CLIENT_CAP:
    {
        struct drm_set_client_cap *cap = (struct drm_set_client_cap *)arg;
        switch (cap->capability)
        {
        case DRM_CLIENT_CAP_ATOMIC:
            return 0;
        case DRM_CLIENT_CAP_UNIVERSAL_PLANES:
            return 0;
        default:
            return -EINVAL;
        }
    }

    case DRM_IOCTL_SET_MASTER:
    {
        return 0;
    }
    case DRM_IOCTL_DROP_MASTER:
    {
        return 0;
    }

    case DRM_IOCTL_MODE_GETGAMMA:
    {
        return 0;
    }
    case DRM_IOCTL_MODE_SETGAMMA:
    {
        return 0;
    }

    case DRM_IOCTL_MODE_DIRTYFB:
    {
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

void *drm_map(void *data, void *addr, uint64_t offset, uint64_t len)
{
    drm_device_t *dev = (drm_device_t *)data;

    map_page_range(get_current_page_dir(false), (uint64_t)addr, offset, len, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

void drm_init()
{
    size_t addr;
    size_t width;
    size_t height;
    size_t bpp;
    size_t cols;
    size_t rows;

    os_terminal_get_screen_info(&addr, &width, &height, &bpp, &cols, &rows);

    struct limine_framebuffer *fb = malloc(sizeof(struct limine_framebuffer));
    fb->address = (void *)addr;
    fb->width = width;
    fb->height = height;
    fb->bpp = bpp;

    char buf[16];
    sprintf(buf, "dri/card%d", 0);
    drm_device_t *drm = malloc(sizeof(drm_device_t));
    drm->id = 1;
    drm->framebuffer = fb;
    regist_dev(buf, NULL, NULL, drm_ioctl, NULL, drm_map, drm);
}

void drm_init_sysfs()
{
    pci_device_t *pci_device = NULL;
    for (int i = 0; i < pci_device_number; i++)
    {
        if (pci_devices[i]->class_code == 0x030000)
        {
            pci_device = pci_devices[i];
            break;
        }
    }

    vfs_node_t dev = vfs_open("/sys/dev/char/226:0/device");

    vfs_node_t boot_vga_node = vfs_child_append(dev, "boot_vga", NULL);
    boot_vga_node->type = file_none;
    boot_vga_node->mode = 0700;
    sysfs_handle_t *handle = malloc(sizeof(sysfs_handle_t));
    sprintf(handle->content, "1");
    handle->node = boot_vga_node;
    boot_vga_node->handle = handle;

    vfs_node_t drm = vfs_child_append(dev, "drm", NULL);
    drm->type = file_dir;
    drm->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    handle->node = drm;
    drm->handle = handle;

    vfs_node_t dev_uevent = vfs_node_alloc(dev, "uevent");
    dev_uevent->type = file_none;
    dev_uevent->mode = 0700;
    sysfs_handle_t *dev_uevent_handle = malloc(sizeof(sysfs_handle_t));
    dev_uevent->handle = dev_uevent_handle;
    dev_uevent_handle->node = dev_uevent;

    if (pci_device)
    {
        sprintf(dev_uevent_handle->content, "PCI_SLOT_NAME=%04x:%02x:%02x.%u\n", pci_device->segment, pci_device->bus, pci_device->slot, pci_device->func);

        vfs_node_t dev_vendor = vfs_node_alloc(dev, "vendor");
        dev_vendor->type = file_none;
        dev_vendor->mode = 0700;
        sysfs_handle_t *dev_vendor_handle = malloc(sizeof(sysfs_handle_t));
        sprintf(dev_vendor_handle->content, "0x%04x\n", pci_device->vendor_id);
        dev_vendor->handle = dev_vendor_handle;

        vfs_node_t dev_subsystem_vendor = vfs_node_alloc(dev, "subsystem_vendor");
        dev_subsystem_vendor->type = file_none;
        dev_subsystem_vendor->mode = 0700;
        sysfs_handle_t *dev_subsystem_vendor_handle = malloc(sizeof(sysfs_handle_t));
        sprintf(dev_subsystem_vendor_handle->content, "0x%04x\n", pci_device->vendor_id);
        dev_subsystem_vendor->handle = dev_subsystem_vendor_handle;

        vfs_node_t dev_device = vfs_node_alloc(dev, "device");
        dev_device->type = file_none;
        dev_device->mode = 0700;
        sysfs_handle_t *dev_device_handle = malloc(sizeof(sysfs_handle_t));
        sprintf(dev_device_handle->content, "0x%04x\n", pci_device->device_id);
        dev_device->handle = dev_device_handle;

        vfs_node_t dev_subsystem_device = vfs_node_alloc(dev, "subsystem_device");
        dev_subsystem_device->type = file_none;
        dev_subsystem_device->mode = 0700;
        sysfs_handle_t *dev_subsystem_device_handle = malloc(sizeof(sysfs_handle_t));
        sprintf(dev_subsystem_device_handle->content, "0x%04x\n", pci_device->device_id);
        dev_subsystem_device->handle = dev_subsystem_device_handle;
    }
    else
    {
        sprintf(dev_uevent_handle->content, "PCI_SLOT_NAME=%04x:%02x:%02x.%u", 0, 0, 0, 0);
    }

    vfs_node_t version = vfs_node_alloc(drm, "version");
    version->type = file_none;
    version->mode = 0700;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    sprintf(handle->content, "drm 1.1.0 20060810");
    version->handle = handle;
    memset(handle, 0, sizeof(sysfs_handle_t));

    vfs_node_t class = vfs_open("/sys/class");
    vfs_node_t drm_link = vfs_node_alloc(class, "drm");
    drm_link->type = file_dir | file_symlink;
    drm_link->mode = 0644;
    drm_link->linkto = drm;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = drm_link;
    drm_link->handle = handle;

    size_t addr;
    size_t width;
    size_t height;
    size_t bpp;
    size_t cols;
    size_t rows;

    os_terminal_get_screen_info(&addr, &width, &height, &bpp, &cols, &rows);

    int i = 0;

    char buf[256];
    sprintf(buf, "card%d", i);
    vfs_node_t cardn = vfs_node_alloc(drm, (const char *)buf);
    cardn->type = file_dir;
    cardn->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = cardn;
    cardn->handle = handle;

    vfs_node_t uevent = vfs_child_append(cardn, "uevent", NULL);
    uevent->type = file_none;
    uevent->mode = 0700;
    sysfs_handle_t *uevent_handle = malloc(sizeof(sysfs_handle_t));
    sprintf(uevent_handle->content, "MAJOR=%d\nMINOR=%d\nDEVNAME=dri/card%d\nSUBSYSTEM=drm_minor\n", 226, 0, i);
    uevent_handle->node = uevent;
    uevent->handle = uevent_handle;

    vfs_node_t cardn_link = vfs_node_alloc(drm_link, (const char *)buf);
    cardn_link->type = file_dir | file_symlink;
    cardn_link->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = cardn_link;
    cardn_link->handle = handle;

    sprintf(buf, "card%d-Virtual-1", i);
    vfs_node_t cardn_virtual = vfs_node_alloc(cardn, (const char *)buf);
    cardn_virtual->type = file_dir;
    cardn_virtual->mode = 0644;

    vfs_node_t subsystem = vfs_child_append(cardn, "subsystem", NULL);
    subsystem->type = file_dir;
    subsystem->mode = 0644;
    sysfs_handle_t *subsystem_handle = malloc(sizeof(sysfs_handle_t));
    memset(subsystem_handle, 0, sizeof(sysfs_handle_t));
    subsystem->handle = subsystem_handle;
    subsystem_handle->node = subsystem;
    subsystem_handle->private_data = NULL;

    vfs_node_t subsystem_link = vfs_child_append(dev, "subsystem", NULL);
    subsystem_link->type = file_dir | file_symlink;
    subsystem_link->mode = 0644;
    subsystem_link->linkto = subsystem;
    handle = malloc(sizeof(sysfs_handle_t));
    handle->node = subsystem_link;
    subsystem_link->handle = handle;

    sprintf(buf, "connector_id");
    vfs_node_t connector_id = vfs_node_alloc(cardn_virtual, (const char *)buf);
    connector_id->type = file_none;
    connector_id->mode = 0700;
    sysfs_handle_t *sysfs_handle = malloc(sizeof(sysfs_handle_t));
    memset(sysfs_handle, 0, sizeof(sysfs_handle_t));
    sprintf(sysfs_handle->content, "%d", i + 1);
    connector_id->handle = sysfs_handle;

    sprintf(buf, "modes");
    vfs_node_t modes = vfs_node_alloc(cardn_virtual, (const char *)buf);
    modes->type = file_none;
    modes->mode = 0700;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    sprintf(handle->content, "%dx%d", width, height);
    modes->handle = handle;

    vfs_node_t device_pci = vfs_node_alloc(dev, "pci");
    device_pci->type = file_dir;
    device_pci->mode = 0700;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = device_pci;
    device_pci->handle = handle;

    vfs_node_t device_subsystem = vfs_node_alloc(dev, "subsystem");
    device_subsystem->type = file_dir | file_symlink;
    device_subsystem->mode = 0700;
    device_subsystem->linkto = device_pci;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = device_subsystem;
    device_subsystem->handle = handle;

    vfs_node_t pci_dir = vfs_node_alloc(device_subsystem, "pci");
    pci_dir->type = file_dir;
    pci_dir->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    handle->node = pci_dir;
    pci_dir->handle = handle;
}
