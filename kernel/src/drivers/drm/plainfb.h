#pragma once

#include <drivers/drm/drm_core.h>
#include <boot/boot.h>

typedef struct plainfb_device {
    boot_framebuffer_t *framebuffer;

    // Framebuffer management
    struct plainfb_dumbbuffer {
        bool used;
        bool direct_backed;
        uint64_t addr;
        uint32_t width;
        uint32_t height;
        uint32_t pitch;
        int refcount;
    } dumbbuffers[32];

    // DRM resources
    drm_connector_t *connectors[16];
    drm_crtc_t *crtcs[16];
    drm_encoder_t *encoders[16];
    drm_resource_manager_t resource_mgr;

    struct plainfb_cursor_state {
        bool enabled;
        bool drawn;
        uint32_t handle;
        int32_t x;
        int32_t y;
        uint32_t width;
        uint32_t height;
        int32_t draw_x;
        int32_t draw_y;
        uint32_t draw_width;
        uint32_t draw_height;
        uint8_t *backup;
        size_t backup_size;
    } cursor;
} plainfb_device_t;

void drm_plainfb_init();
