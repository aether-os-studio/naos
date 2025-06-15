#include <drivers/drm/drm.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <arch/arch.h>
#include <mm/mm.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

static ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    drm_device_t *dev = (drm_device_t *)data;

    switch (cmd)
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
        // 返回基本显示资源信息
        res->count_fbs = 1;
        res->count_crtcs = 1;
        res->count_connectors = 1;
        res->count_encoders = 1;
        return 0;
    }

    case DRM_IOCTL_MODE_CREATE_DUMB:
    {
        struct drm_mode_create_dumb *create = (struct drm_mode_create_dumb *)arg;
        // 创建简单的显示缓冲区
        create->height = dev->framebuffer->height;
        create->width = dev->framebuffer->width;
        create->bpp = dev->framebuffer->bpp;
        create->size = create->height * create->width * 4;
        create->pitch = dev->framebuffer->pitch;
        create->handle = 1;
        return 0;
    }

    case DRM_IOCTL_MODE_MAP_DUMB:
    {
        struct drm_mode_map_dumb *map = (struct drm_mode_map_dumb *)arg;
        map->offset = translate_address(get_current_page_dir(false), (uint64_t)dev->framebuffer->address);
        return 0;
    }

    case DRM_IOCTL_MODE_GETCONNECTOR:
    {
        struct drm_mode_get_connector *conn = (struct drm_mode_get_connector *)arg;
        conn->connection = DRM_MODE_CONNECTOR_VGA;
        conn->count_modes = 1;
        conn->count_props = 0;
        conn->count_encoders = 1;
        return 0;
    }
    case DRM_IOCTL_MODE_GETFB:
    {
        struct drm_mode_fb_cmd fb;
        fb.fb_id = dev->id;
        fb.width = dev->framebuffer->width,
        fb.height = dev->framebuffer->height,
        fb.pitch = dev->framebuffer->pitch,
        fb.bpp = dev->framebuffer->bpp,
        fb.depth = 24,
        fb.handle = (uint32_t)translate_address(get_current_page_dir(false), (uint64_t)dev->framebuffer->address);
        memcpy((void *)arg, &fb, sizeof(fb));
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

void drm_init()
{
    for (int i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char buf[16];
        sprintf(buf, "dri/card%d", i);
        drm_device_t *drm = malloc(sizeof(drm_device_t));
        drm->id = i + 1;
        drm->framebuffer = framebuffer_request.response->framebuffers[i];
        regist_dev(buf, NULL, NULL, drm_ioctl, NULL, NULL, drm);
    }
}

void drm_init_sysfs()
{
    vfs_node_t dev = vfs_open("/sys/dev/char/226:0/device");
    vfs_node_t drm = vfs_child_append(dev, "drm", NULL);
    drm->type = file_dir;
    drm->mode = 0644;

    vfs_node_t version = vfs_node_alloc(drm, "version");
    version->type = file_none;
    version->mode = 0700;
    sysfs_handle_t *handle = malloc(sizeof(sysfs_handle_t));
    memset(handle, 0, sizeof(sysfs_handle_t));
    sprintf(handle->content, "drm 1.1.0 20060810");
    version->handle = handle;
    memset(handle, 0, sizeof(sysfs_handle_t));

    vfs_node_t class = vfs_open("/sys/class");
    vfs_node_t drm_link = vfs_node_alloc(class, "drm");
    drm_link->type = file_symlink | file_dir;
    drm_link->mode = 0644;

    for (int i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char buf[256];
        sprintf(buf, "card%d", i);
        vfs_node_t cardn = vfs_node_alloc(drm, (const char *)buf);
        cardn->type = file_dir;
        cardn->mode = 0644;

        vfs_node_t cardn_link = vfs_node_alloc(drm_link, (const char *)buf);
        cardn_link->type = file_symlink | file_dir;
        cardn_link->mode = 0644;
        cardn_link->linkname = vfs_get_fullpath(cardn);

        sprintf(buf, "card%d-Virtual-1", i);
        vfs_node_t cardn_virtual = vfs_node_alloc(cardn, (const char *)buf);
        cardn_virtual->type = file_dir;
        cardn_virtual->mode = 0644;

        vfs_node_t uevent_link = vfs_child_append(cardn, "uevent", NULL);
        uevent_link->type = file_symlink | file_none;
        uevent_link->mode = 0644;
        sprintf(buf, "/sys/class/drm/card%d/subsystem/uevent", i);
        uevent_link->linkname = strdup(buf);

        vfs_node_t subsystem = vfs_child_append(cardn, "subsystem", NULL);
        subsystem->type = file_dir;
        subsystem->mode = 0644;
        sysfs_handle_t *subsystem_handle = malloc(sizeof(sysfs_handle_t));
        memset(subsystem_handle, 0, sizeof(sysfs_handle_t));
        subsystem->handle = subsystem_handle;
        subsystem_handle->node = subsystem;
        subsystem_handle->private_data = NULL;

        vfs_node_t uevent = vfs_child_append(subsystem, "uevent", NULL);
        uevent->type = file_none;
        uevent->mode = 0700;
        sysfs_handle_t *uevent_handle = malloc(sizeof(sysfs_handle_t));
        sprintf(uevent_handle->content, "MAJOR=%d\nMINOR=%d\nDEVNAME=dri/card%d\nSUBSYSTEM=drm_minor\n", 226, 0, i);
        uevent->handle = uevent_handle;

        sprintf(buf, "connector_id");
        vfs_node_t connector_id = vfs_node_alloc(cardn_virtual, (const char *)buf);
        connector_id->type = file_none;
        connector_id->mode = 0700;
        sysfs_handle_t *handle = malloc(sizeof(sysfs_handle_t));
        memset(handle, 0, sizeof(sysfs_handle_t));
        sprintf(handle->content, "%d", i + 1);
        connector_id->handle = handle;

        sprintf(buf, "modes");
        vfs_node_t modes = vfs_node_alloc(cardn_virtual, (const char *)buf);
        modes->type = file_none;
        modes->mode = 0700;
        handle = malloc(sizeof(sysfs_handle_t));
        memset(handle, 0, sizeof(sysfs_handle_t));
        sprintf(handle->content, "%dx%d", framebuffer_request.response->framebuffers[i]->width, framebuffer_request.response->framebuffers[i]->height);
        modes->handle = handle;
    }
}
