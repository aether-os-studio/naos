#include <drivers/drm/drm.h>
#include <fs/vfs/dev.h>
#include <mm/mm.h>

static struct drm_device primary_dev;

extern volatile struct limine_framebuffer_request framebuffer_request;

static ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    struct drm_device *dev = data;

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
            return -EINVAL;
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
        create->height = dev->height;
        create->width = dev->width;
        create->bpp = 32;
        create->size = create->height * create->width * 4;
        create->pitch = create->width * 4;
        create->handle = 1; // 简单句柄管理
        return 0;
    }

    case DRM_IOCTL_MODE_MAP_DUMB:
    {
        struct drm_mode_map_dumb *map = (struct drm_mode_map_dumb *)arg;
        map->offset = (uint64_t)dev->vaddr; // 直接映射framebuffer地址
        return 0;
    }

    case DRM_IOCTL_MODE_GETCONNECTOR:
    {
        struct drm_mode_get_connector *conn = (struct drm_mode_get_connector *)arg;
        conn->connection = DRM_MODE_CONNECTED;
        conn->count_modes = 1;
        conn->count_props = 0;
        conn->count_encoders = 1;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

void drm_init()
{
    if (framebuffer_request.response &&
        framebuffer_request.response->framebuffer_count > 0)
    {
        struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];

        primary_dev.width = fb->width;
        primary_dev.height = fb->height;
        primary_dev.pitch = fb->pitch;
        primary_dev.vaddr = fb->address;
        primary_dev.paddr = (uint64_t)fb->address;
    }

    regist_dev("dri/card0", NULL, NULL, drm_ioctl, NULL, &primary_dev);
}
