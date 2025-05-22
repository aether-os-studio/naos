#pragma once

#include <libs/klibc.h>

#define DRM_IOCTL_BASE 'd'
#define DRM_IOCTL_VERSION _IOR(DRM_IOCTL_BASE, 0x00, uint32_t)
#define DRM_IOCTL_GET_CAP _IOWR(DRM_IOCTL_BASE, 0x0C, struct drm_get_cap)
#define DRM_IOCTL_MODE_GETRESOURCES _IOR(DRM_IOCTL_BASE, 0xA0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_CREATE_DUMB _IOWR(DRM_IOCTL_BASE, 0xB2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB _IOWR(DRM_IOCTL_BASE, 0xB3, struct drm_mode_map_dumb)
#define DRM_IOCTL_MODE_GETCONNECTOR _IOWR(DRM_IOCTL_BASE, 0xB7, struct drm_mode_get_connector)

#define DRM_CAP_DUMB_BUFFER 0x1
#define DRM_MODE_CONNECTED 1

struct drm_device
{
    uint32_t flags;  // 设备标志位
    uint32_t width;  // 显示宽度(像素)
    uint32_t height; // 显示高度(像素)
    uint32_t pitch;  // 每行字节数
    void *vaddr;     // 显存虚拟地址
    uint64_t paddr;  // 显存物理地址
};

struct drm_get_cap
{
    uint64_t capability;
    uint64_t value;
};

struct drm_mode_card_res
{
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width, max_width;
    uint32_t min_height, max_height;
};

struct drm_mode_create_dumb
{
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct drm_mode_map_dumb
{
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
};

struct drm_mode_get_connector
{
    uint64_t encoders_ptr;
    uint64_t modes_ptr;
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint32_t count_modes;
    uint32_t count_props;
    uint32_t count_encoders;
    uint32_t encoder_id;
    uint32_t connector_id;
    uint32_t connector_type;
    uint32_t connector_type_id;
    uint32_t connection;
    uint32_t mm_width, mm_height;
    uint32_t subpixel;
    uint32_t pad;
};

void drm_init();
