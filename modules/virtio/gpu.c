// Copyright (C) 2025  lihanrui2913
#include "gpu.h"
#include "pci.h"
#include <libs/aether/drm.h>
#include <libs/aether/mm.h>
#include <libs/klibc.h>

virtio_gpu_device_t *virtio_gpu_devices[MAX_VIRTIO_GPU_DEVICES];
uint32_t virtio_gpu_devices_count = 0;

static bool virtio_gpu_handle_to_index(uint32_t handle, uint32_t *idx) {
    if (!idx || handle == 0 || handle > 32) {
        return false;
    }

    *idx = handle - 1;
    return true;
}

static int virtio_gpu_alloc_resource_id(virtio_gpu_device_t *gpu_dev,
                                        uint32_t *resource_id) {
    if (!gpu_dev || !resource_id) {
        return -EINVAL;
    }

    uint32_t id = gpu_dev->next_resource_id++;
    if (id == 0) {
        id = gpu_dev->next_resource_id++;
    }

    *resource_id = id;
    return 0;
}

// Send control command to GPU
static int virtio_gpu_send_command(virtio_gpu_device_t *gpu_dev, void *cmd,
                                   size_t cmd_size, void *resp,
                                   size_t resp_size) {
    if (!gpu_dev || !cmd || !resp || cmd_size == 0 || resp_size == 0) {
        return -EINVAL;
    }

    virtio_buffer_t bufs[2];
    bool writable[2];

    // Command buffer (write-only)
    bufs[0].addr = (uint64_t)cmd;
    bufs[0].size = cmd_size;
    writable[0] = false;

    // Response buffer (read-only)
    bufs[1].addr = (uint64_t)resp;
    bufs[1].size = resp_size;
    writable[1] = true;

    spin_lock(&gpu_dev->lock);

    uint16_t desc_idx =
        virt_queue_add_buf(gpu_dev->control_queue, bufs, 2, writable);
    if (desc_idx == 0xFFFF) {
        spin_unlock(&gpu_dev->lock);
        return -1;
    }

    virt_queue_submit_buf(gpu_dev->control_queue, desc_idx);
    virt_queue_notify(gpu_dev->driver, gpu_dev->control_queue);

    // Wait for response
    uint32_t len;
    uint16_t used_desc_idx;
    while ((used_desc_idx = virt_queue_get_used_buf(gpu_dev->control_queue,
                                                    &len)) == 0xFFFF) {
        arch_pause();
    }

    virt_queue_free_desc(gpu_dev->control_queue, used_desc_idx);
    spin_unlock(&gpu_dev->lock);
    return 0;
}

// Get display information from GPU
int virtio_gpu_get_display_info(virtio_gpu_device_t *gpu_dev) {
    virtio_gpu_ctrl_hdr_t cmd = {.type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
                                 .flags = 0,
                                 .fence_id = 0,
                                 .ctx_id = 0,
                                 .padding = 0};

    virtio_gpu_resp_display_info_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        return -1;
    }

    // Count enabled displays
    gpu_dev->num_displays = 0;
    for (uint32_t i = 0; i < 16; i++) {
        if (resp.displays[i].enabled) {
            gpu_dev->scanout_ids[gpu_dev->num_displays] = i;
            memcpy(&gpu_dev->displays[gpu_dev->num_displays], &resp.displays[i],
                   sizeof(virtio_gpu_display_one_t));
            gpu_dev->num_displays++;
        }
    }

    return gpu_dev->num_displays;
}

// Create 2D resource
int virtio_gpu_create_resource(virtio_gpu_device_t *gpu_dev,
                               uint32_t resource_id, uint32_t format,
                               uint32_t width, uint32_t height) {
    virtio_gpu_resource_create_2d_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .format = format,
        .width = width,
        .height = height,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Attach backing store to resource
int virtio_gpu_attach_backing(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id, uint64_t addr,
                              uint32_t length) {
    // First send the attach command
    virtio_gpu_resource_attach_backing_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .nr_entries = 1,
        .mem_entry = {.addr = addr, .length = length, .padding = 0}};

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

int virtio_gpu_detach_backing(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id) {
    virtio_gpu_resource_detach_backing_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .padding = 0,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

int virtio_gpu_unref_resource(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id) {
    virtio_gpu_resource_unref_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_UNREF,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .padding = 0,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Set scanout (display resource on screen)
int virtio_gpu_set_scanout(virtio_gpu_device_t *gpu_dev, uint32_t scanout_id,
                           uint32_t resource_id, uint32_t width,
                           uint32_t height, uint32_t x, uint32_t y) {
    virtio_gpu_set_scanout_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_SET_SCANOUT,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .scanout_id = scanout_id,
        .resource_id = resource_id,
        .r.width = width,
        .r.height = height,
        .r.x = x,
        .r.y = y,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Transfer data to host (GPU)
int virtio_gpu_transfer_to_host(virtio_gpu_device_t *gpu_dev,
                                uint32_t resource_id, uint32_t width,
                                uint32_t height, uint32_t x, uint32_t y) {
    virtio_gpu_transfer_to_host_2d_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .padding = 0,
        .offset = 0,
        .r.width = width,
        .r.height = height,
        .r.x = x,
        .r.y = y};

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Flush resource (make changes visible)
int virtio_gpu_resource_flush(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id, uint32_t width,
                              uint32_t height, uint32_t x, uint32_t y) {
    virtio_gpu_resource_flush_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .resource_id = resource_id,
        .padding = 0,
        .r.width = width,
        .r.height = height,
        .r.x = x,
        .r.y = y};

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Update cursor
int virtio_gpu_update_cursor(virtio_gpu_device_t *gpu_dev, uint32_t resource_id,
                             uint32_t pos_x, uint32_t pos_y, uint32_t hot_x,
                             uint32_t hot_y) {
    virtio_gpu_update_cursor_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_UPDATE_CURSOR,
                .flags = 0,
                .fence_id = 0,
                .ctx_id = 0,
                .padding = 0},
        .pos_x = pos_x,
        .pos_y = pos_y,
        .hot_x = hot_x,
        .hot_y = hot_y,
        .padding = 0,
        .resource_id = resource_id};

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

// Move cursor
int virtio_gpu_move_cursor(virtio_gpu_device_t *gpu_dev, uint32_t resource_id,
                           uint32_t pos_x, uint32_t pos_y) {
    virtio_gpu_move_cursor_t cmd = {.hdr = {.type = VIRTIO_GPU_CMD_MOVE_CURSOR,
                                            .flags = 0,
                                            .fence_id = 0,
                                            .ctx_id = 0,
                                            .padding = 0},
                                    .pos_x = pos_x,
                                    .pos_y = pos_y,
                                    .padding = 0,
                                    .resource_id = resource_id};

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        return -1;
    }

    return 0;
}

static int virtio_gpu_get_scanout_from_crtc(virtio_gpu_device_t *gpu_dev,
                                            uint32_t crtc_id,
                                            uint32_t *scanout_id,
                                            uint32_t *display_idx) {
    if (!gpu_dev || !scanout_id) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < gpu_dev->num_displays; i++) {
        if (gpu_dev->crtcs[i] && gpu_dev->crtcs[i]->id == crtc_id) {
            *scanout_id = gpu_dev->scanout_ids[i];
            if (display_idx) {
                *display_idx = i;
            }
            return 0;
        }
    }

    return -ENOENT;
}

static int virtio_gpu_get_fb_from_fb_id(virtio_gpu_device_t *gpu_dev,
                                        uint32_t fb_id,
                                        drm_framebuffer_t **drm_fb_out,
                                        struct virtio_gpu_framebuffer **fb_out,
                                        uint32_t *fb_idx_out) {
    if (!gpu_dev || !drm_fb_out || !fb_out) {
        return -EINVAL;
    }

    drm_framebuffer_t *drm_fb =
        drm_framebuffer_get(&gpu_dev->resource_mgr, fb_id);
    if (!drm_fb) {
        return -ENOENT;
    }

    uint32_t fb_idx = 0;
    if (!virtio_gpu_handle_to_index(drm_fb->handle, &fb_idx) ||
        gpu_dev->framebuffers[fb_idx].resource_id == 0) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
        return -EINVAL;
    }

    *drm_fb_out = drm_fb;
    *fb_out = &gpu_dev->framebuffers[fb_idx];
    if (fb_idx_out) {
        *fb_idx_out = fb_idx;
    }
    return 0;
}

static int virtio_gpu_present_region(virtio_gpu_device_t *gpu_dev,
                                     struct virtio_gpu_framebuffer *fb,
                                     uint32_t scanout_id, uint32_t x,
                                     uint32_t y, uint32_t width,
                                     uint32_t height, bool set_scanout) {
    if (!gpu_dev || !fb || fb->resource_id == 0) {
        return -EINVAL;
    }

    if (width == 0) {
        width = fb->width;
    }
    if (height == 0) {
        height = fb->height;
    }

    if (x >= fb->width || y >= fb->height) {
        return -EINVAL;
    }

    if (width > fb->width - x) {
        width = fb->width - x;
    }
    if (height > fb->height - y) {
        height = fb->height - y;
    }

    int ret = virtio_gpu_transfer_to_host(gpu_dev, fb->resource_id, width,
                                          height, x, y);
    if (ret != 0) {
        return ret;
    }

    if (set_scanout) {
        ret = virtio_gpu_set_scanout(gpu_dev, scanout_id, fb->resource_id,
                                     width, height, x, y);
        if (ret != 0) {
            return ret;
        }
    }

    return virtio_gpu_resource_flush(gpu_dev, fb->resource_id, width, height, x,
                                     y);
}

// DRM device operations
static int virtio_gpu_get_display_info_drm(drm_device_t *drm_dev,
                                           uint32_t *width, uint32_t *height,
                                           uint32_t *bpp) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (gpu_dev && gpu_dev->num_displays > 0) {
        *width = gpu_dev->displays[0].rect.width;
        *height = gpu_dev->displays[0].rect.height;
        *bpp = 32;
        return 0;
    }
    return -ENODEV;
}

static int virtio_gpu_create_dumb(drm_device_t *drm_dev,
                                  struct drm_mode_create_dumb *args) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !args || args->width == 0 || args->height == 0) {
        return -EINVAL;
    }

    if (args->bpp == 0) {
        args->bpp = 32;
    }

    uint32_t bytes_per_pixel = args->bpp / 8;
    if (bytes_per_pixel == 0) {
        return -EINVAL;
    }

    args->pitch = PADDING_UP(args->width * bytes_per_pixel, 64);
    args->size = args->height * args->pitch;

    uint64_t alloc_size =
        PADDING_UP((uint64_t)args->size, (uint64_t)DEFAULT_PAGE_SIZE);

    for (uint32_t i = 0; i < 32; i++) {
        if (gpu_dev->framebuffers[i].resource_id == 0) {
            uint32_t resource_id = 0;
            if (virtio_gpu_alloc_resource_id(gpu_dev, &resource_id) != 0) {
                return -ENOSPC;
            }

            int ret = virtio_gpu_create_resource(
                gpu_dev, resource_id, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
                args->width, args->height);
            if (ret != 0) {
                return -EIO;
            }

            gpu_dev->framebuffers[i].addr =
                alloc_frames(alloc_size / DEFAULT_PAGE_SIZE);
            if (!gpu_dev->framebuffers[i].addr) {
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                return -ENOMEM;
            }

            memset((void *)phys_to_virt(gpu_dev->framebuffers[i].addr), 0,
                   alloc_size);

            ret = virtio_gpu_attach_backing(gpu_dev, resource_id,
                                            gpu_dev->framebuffers[i].addr,
                                            args->pitch * args->height);
            if (ret != 0) {
                free_frames(gpu_dev->framebuffers[i].addr,
                            alloc_size / DEFAULT_PAGE_SIZE);
                gpu_dev->framebuffers[i].addr = 0;
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                return -EIO;
            }

            gpu_dev->framebuffers[i].resource_id = resource_id;
            gpu_dev->framebuffers[i].width = args->width;
            gpu_dev->framebuffers[i].height = args->height;
            gpu_dev->framebuffers[i].pitch = args->pitch;
            gpu_dev->framebuffers[i].format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
            gpu_dev->framebuffers[i].size = alloc_size;
            gpu_dev->framebuffers[i].refcount = 1;
            args->handle = i + 1;
            return 0;
        }
    }

    return -ENOSPC;
}

static int virtio_gpu_destroy_dumb(drm_device_t *drm_dev, uint32_t handle) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    uint32_t idx = 0;

    if (!gpu_dev || !virtio_gpu_handle_to_index(handle, &idx) ||
        gpu_dev->framebuffers[idx].resource_id == 0) {
        return -EINVAL;
    }

    if (--gpu_dev->framebuffers[idx].refcount == 0) {
        virtio_gpu_detach_backing(gpu_dev,
                                  gpu_dev->framebuffers[idx].resource_id);
        virtio_gpu_unref_resource(gpu_dev,
                                  gpu_dev->framebuffers[idx].resource_id);

        if (gpu_dev->framebuffers[idx].addr &&
            gpu_dev->framebuffers[idx].size) {
            free_frames(gpu_dev->framebuffers[idx].addr,
                        gpu_dev->framebuffers[idx].size / DEFAULT_PAGE_SIZE);
        }

        memset(&gpu_dev->framebuffers[idx], 0,
               sizeof(gpu_dev->framebuffers[idx]));
    }

    return 0;
}

static int virtio_gpu_map_dumb(drm_device_t *drm_dev,
                               struct drm_mode_map_dumb *args) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    uint32_t idx = 0;

    if (!gpu_dev || !args || !virtio_gpu_handle_to_index(args->handle, &idx) ||
        gpu_dev->framebuffers[idx].resource_id == 0) {
        return -EINVAL;
    }

    args->offset = gpu_dev->framebuffers[idx].addr;
    return 0;
}

static int virtio_gpu_add_fb(drm_device_t *drm_dev,
                             struct drm_mode_fb_cmd *fb_cmd) {
    virtio_gpu_device_t *device = drm_dev->data;
    uint32_t idx = 0;
    if (!device || !fb_cmd ||
        !virtio_gpu_handle_to_index(fb_cmd->handle, &idx) ||
        device->framebuffers[idx].resource_id == 0) {
        return -EINVAL;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&device->resource_mgr, device);
    if (!fb) {
        return -ENOMEM;
    }

    fb->width = fb_cmd->width;
    fb->height = fb_cmd->height;
    fb->pitch = fb_cmd->pitch;
    fb->bpp = fb_cmd->bpp;
    fb->depth = fb_cmd->depth;
    fb->handle = fb_cmd->handle;
    fb->format = DRM_FORMAT_BGRX8888;

    fb_cmd->fb_id = fb->id;

    return 0;
}

static int virtio_gpu_add_fb2(drm_device_t *drm_dev,
                              struct drm_mode_fb_cmd2 *fb_cmd) {
    virtio_gpu_device_t *device = drm_dev->data;
    uint32_t idx = 0;
    if (!device || !fb_cmd || fb_cmd->handles[0] == 0 ||
        !virtio_gpu_handle_to_index(fb_cmd->handles[0], &idx) ||
        device->framebuffers[idx].resource_id == 0) {
        return -EINVAL;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&device->resource_mgr, device);
    if (!fb) {
        return -ENOMEM;
    }

    fb->width = fb_cmd->width;
    fb->height = fb_cmd->height;
    fb->pitch = fb_cmd->pitches[0];
    fb->bpp = 32;
    fb->depth = 24;
    fb->handle = fb_cmd->handles[0];
    fb->format = fb_cmd->pixel_format;
    fb->modifier = fb_cmd->modifier[0];

    fb_cmd->fb_id = fb->id;

    return 0;
}

static int virtio_gpu_page_flip(drm_device_t *drm_dev,
                                struct drm_mode_crtc_page_flip *flip) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !flip) {
        return -ENODEV;
    }

    uint32_t scanout_id = 0;
    uint32_t display_idx = 0;
    if (virtio_gpu_get_scanout_from_crtc(gpu_dev, flip->crtc_id, &scanout_id,
                                         &display_idx) != 0) {
        return -EINVAL;
    }

    drm_framebuffer_t *drm_fb = NULL;
    struct virtio_gpu_framebuffer *fb = NULL;
    int ret =
        virtio_gpu_get_fb_from_fb_id(gpu_dev, flip->fb_id, &drm_fb, &fb, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = virtio_gpu_present_region(gpu_dev, fb, scanout_id, 0, 0, fb->width,
                                    fb->height, true);
    if (ret == 0 && gpu_dev->crtcs[display_idx]) {
        gpu_dev->crtcs[display_idx]->fb_id = flip->fb_id;
        if (gpu_dev->planes[display_idx]) {
            gpu_dev->planes[display_idx]->fb_id = flip->fb_id;
        }
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);

    if (ret != 0) {
        return -EIO;
    }

    if (flip->flags & DRM_MODE_PAGE_FLIP_EVENT) {
        drm_post_event(drm_dev, DRM_EVENT_FLIP_COMPLETE, flip->user_data);
    }

    return 0;
}

static int virtio_gpu_atomic_commit(drm_device_t *drm_dev,
                                    struct drm_mode_atomic *atomic) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !atomic) {
        return -ENODEV;
    }

    if (atomic->flags & ~DRM_MODE_ATOMIC_FLAGS) {
        return -EINVAL;
    }

    if (atomic->count_objs == 0) {
        return 0;
    }

    uint32_t *obj_ids = (uint32_t *)(uintptr_t)atomic->objs_ptr;
    uint32_t *obj_prop_counts = (uint32_t *)(uintptr_t)atomic->count_props_ptr;
    uint32_t *prop_ids = (uint32_t *)(uintptr_t)atomic->props_ptr;
    uint64_t *prop_values = (uint64_t *)(uintptr_t)atomic->prop_values_ptr;

    if (!obj_ids || !obj_prop_counts || !prop_ids || !prop_values) {
        return -EINVAL;
    }

    bool test_only = (atomic->flags & DRM_MODE_ATOMIC_TEST_ONLY) != 0;
    uint64_t prop_idx = 0;

    for (uint32_t i = 0; i < atomic->count_objs; i++) {
        uint32_t obj_id = obj_ids[i];
        uint32_t count = obj_prop_counts[i];

        enum {
            ATOMIC_OBJ_UNKNOWN = 0,
            ATOMIC_OBJ_PLANE,
            ATOMIC_OBJ_CRTC,
            ATOMIC_OBJ_CONNECTOR,
        } obj_type = ATOMIC_OBJ_UNKNOWN;

        for (uint32_t j = 0; j < count; j++) {
            switch (prop_ids[prop_idx + j]) {
            case DRM_PROPERTY_ID_PLANE_TYPE:
            case DRM_PROPERTY_ID_FB_ID:
            case DRM_PROPERTY_ID_CRTC_X:
            case DRM_PROPERTY_ID_CRTC_Y:
            case DRM_PROPERTY_ID_CRTC_W:
            case DRM_PROPERTY_ID_CRTC_H:
            case DRM_PROPERTY_ID_CRTC_ID:
            case DRM_PROPERTY_ID_SRC_X:
            case DRM_PROPERTY_ID_SRC_Y:
            case DRM_PROPERTY_ID_SRC_W:
            case DRM_PROPERTY_ID_SRC_H:
                obj_type = ATOMIC_OBJ_PLANE;
                break;
            case DRM_CRTC_ACTIVE_PROP_ID:
            case DRM_CRTC_MODE_ID_PROP_ID:
                obj_type = ATOMIC_OBJ_CRTC;
                break;
            case DRM_CONNECTOR_DPMS_PROP_ID:
            case DRM_CONNECTOR_CRTC_ID_PROP_ID:
                obj_type = ATOMIC_OBJ_CONNECTOR;
                break;
            default:
                break;
            }

            if (obj_type != ATOMIC_OBJ_UNKNOWN) {
                break;
            }
        }

        drm_plane_t *plane = NULL;
        drm_crtc_t *crtc = NULL;
        drm_connector_t *connector = NULL;

        if (obj_type == ATOMIC_OBJ_PLANE) {
            plane = drm_plane_get(&gpu_dev->resource_mgr, obj_id);
            if (!plane) {
                return -ENOENT;
            }
        } else if (obj_type == ATOMIC_OBJ_CRTC) {
            crtc = drm_crtc_get(&gpu_dev->resource_mgr, obj_id);
            if (!crtc) {
                return -ENOENT;
            }
        } else if (obj_type == ATOMIC_OBJ_CONNECTOR) {
            connector = drm_connector_get(&gpu_dev->resource_mgr, obj_id);
            if (!connector) {
                return -ENOENT;
            }
        }

        for (uint32_t j = 0; j < count; j++, prop_idx++) {
            uint32_t prop_id = prop_ids[prop_idx];
            uint64_t value = prop_values[prop_idx];

            switch (prop_id) {
            case DRM_PROPERTY_ID_PLANE_TYPE:
                if (!plane || value != plane->plane_type) {
                    if (connector) {
                        drm_connector_free(&gpu_dev->resource_mgr,
                                           connector->id);
                    }
                    if (crtc) {
                        drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                    }
                    if (plane) {
                        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
                    }
                    return -EINVAL;
                }
                break;

            case DRM_PROPERTY_ID_FB_ID: {
                if (!plane) {
                    continue;
                }

                if (value != 0) {
                    drm_framebuffer_t *drm_fb = drm_framebuffer_get(
                        &gpu_dev->resource_mgr, (uint32_t)value);
                    if (!drm_fb) {
                        if (connector) {
                            drm_connector_free(&gpu_dev->resource_mgr,
                                               connector->id);
                        }
                        if (crtc) {
                            drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                        }
                        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
                        return -ENOENT;
                    }

                    uint32_t fb_idx = 0;
                    if (!virtio_gpu_handle_to_index(drm_fb->handle, &fb_idx) ||
                        gpu_dev->framebuffers[fb_idx].resource_id == 0) {
                        drm_framebuffer_free(&gpu_dev->resource_mgr,
                                             drm_fb->id);
                        if (connector) {
                            drm_connector_free(&gpu_dev->resource_mgr,
                                               connector->id);
                        }
                        if (crtc) {
                            drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                        }
                        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
                        return -EINVAL;
                    }

                    drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
                }

                if (!test_only) {
                    plane->fb_id = (uint32_t)value;
                }
                break;
            }

            case DRM_PROPERTY_ID_CRTC_ID:
                if (plane && !test_only) {
                    plane->crtc_id = (uint32_t)value;
                }
                break;

            case DRM_PROPERTY_ID_CRTC_X:
            case DRM_PROPERTY_ID_CRTC_Y:
            case DRM_PROPERTY_ID_CRTC_W:
            case DRM_PROPERTY_ID_CRTC_H:
                if (plane) {
                    uint32_t target_crtc_id = plane->crtc_id;
                    if (target_crtc_id) {
                        drm_crtc_t *target_crtc = drm_crtc_get(
                            &gpu_dev->resource_mgr, target_crtc_id);
                        if (!target_crtc) {
                            if (connector) {
                                drm_connector_free(&gpu_dev->resource_mgr,
                                                   connector->id);
                            }
                            if (crtc) {
                                drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                            }
                            drm_plane_free(&gpu_dev->resource_mgr, plane->id);
                            return -ENOENT;
                        }

                        if (!test_only) {
                            if (prop_id == DRM_PROPERTY_ID_CRTC_X) {
                                target_crtc->x = (uint32_t)value;
                            } else if (prop_id == DRM_PROPERTY_ID_CRTC_Y) {
                                target_crtc->y = (uint32_t)value;
                            } else if (prop_id == DRM_PROPERTY_ID_CRTC_W) {
                                target_crtc->w = (uint32_t)value;
                            } else {
                                target_crtc->h = (uint32_t)value;
                            }
                        }

                        drm_crtc_free(&gpu_dev->resource_mgr, target_crtc->id);
                    }
                }
                break;

            case DRM_PROPERTY_ID_SRC_X:
            case DRM_PROPERTY_ID_SRC_Y:
            case DRM_PROPERTY_ID_SRC_W:
            case DRM_PROPERTY_ID_SRC_H:
                break;

            case DRM_CRTC_ACTIVE_PROP_ID:
                if (crtc && !test_only) {
                    crtc->mode_valid = (value != 0);
                }
                break;

            case DRM_CRTC_MODE_ID_PROP_ID:
                break;

            case DRM_CONNECTOR_DPMS_PROP_ID:
                if (value > DRM_MODE_DPMS_OFF) {
                    if (connector) {
                        drm_connector_free(&gpu_dev->resource_mgr,
                                           connector->id);
                    }
                    if (crtc) {
                        drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                    }
                    if (plane) {
                        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
                    }
                    return -EINVAL;
                }
                break;

            case DRM_CONNECTOR_CRTC_ID_PROP_ID:
                if (connector && !test_only) {
                    connector->crtc_id = (uint32_t)value;
                }
                break;

            default:
                break;
            }
        }

        if (connector) {
            drm_connector_free(&gpu_dev->resource_mgr, connector->id);
        }
        if (crtc) {
            drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
        }
        if (plane) {
            drm_plane_free(&gpu_dev->resource_mgr, plane->id);
        }
    }

    if (test_only) {
        return 0;
    }

    for (uint32_t i = 0; i < gpu_dev->num_displays; i++) {
        drm_plane_t *plane = gpu_dev->planes[i];
        drm_crtc_t *crtc = gpu_dev->crtcs[i];
        if (!plane || !crtc) {
            continue;
        }

        if (plane->fb_id == 0 || crtc->mode_valid == 0) {
            int ret = virtio_gpu_set_scanout(gpu_dev, gpu_dev->scanout_ids[i],
                                             0, 0, 0, 0, 0);
            if (ret != 0) {
                return -EIO;
            }
            crtc->fb_id = 0;
            continue;
        }

        drm_framebuffer_t *drm_fb = NULL;
        struct virtio_gpu_framebuffer *fb = NULL;
        int ret = virtio_gpu_get_fb_from_fb_id(gpu_dev, plane->fb_id, &drm_fb,
                                               &fb, NULL);
        if (ret != 0) {
            return ret;
        }

        uint32_t present_w = crtc->w ? crtc->w : fb->width;
        uint32_t present_h = crtc->h ? crtc->h : fb->height;

        ret = virtio_gpu_present_region(gpu_dev, fb, gpu_dev->scanout_ids[i],
                                        crtc->x, crtc->y, present_w, present_h,
                                        true);
        drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
        if (ret != 0) {
            return -EIO;
        }

        crtc->fb_id = plane->fb_id;
    }

    if (atomic->flags & DRM_MODE_PAGE_FLIP_EVENT) {
        drm_post_event(drm_dev, DRM_EVENT_FLIP_COMPLETE, atomic->user_data);
    }

    return 0;
}

static int virtio_gpu_dirty_fb(drm_device_t *drm_dev,
                               struct drm_mode_fb_dirty_cmd *cmd) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !cmd || (cmd->flags & ~DRM_MODE_FB_DIRTY_FLAGS)) {
        return -EINVAL;
    }

    drm_framebuffer_t *drm_fb = NULL;
    struct virtio_gpu_framebuffer *fb = NULL;
    int ret =
        virtio_gpu_get_fb_from_fb_id(gpu_dev, cmd->fb_id, &drm_fb, &fb, NULL);
    if (ret != 0) {
        return ret;
    }

    if (cmd->num_clips == 0 || cmd->clips_ptr == 0) {
        ret = virtio_gpu_present_region(gpu_dev, fb, 0, 0, 0, fb->width,
                                        fb->height, false);
        drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
        return ret ? -EIO : 0;
    }

    uint32_t clips_count = cmd->num_clips;
    if (clips_count > DRM_MODE_FB_DIRTY_MAX_CLIPS) {
        clips_count = DRM_MODE_FB_DIRTY_MAX_CLIPS;
    }

    drm_clip_rect_t *clips = (drm_clip_rect_t *)(uintptr_t)cmd->clips_ptr;
    for (uint32_t i = 0; i < clips_count; i++) {
        uint32_t x = clips[i].x1;
        uint32_t y = clips[i].y1;
        uint32_t w = clips[i].x2 > clips[i].x1 ? clips[i].x2 - clips[i].x1 : 0;
        uint32_t h = clips[i].y2 > clips[i].y1 ? clips[i].y2 - clips[i].y1 : 0;
        if (w == 0 || h == 0) {
            continue;
        }

        ret = virtio_gpu_present_region(gpu_dev, fb, 0, x, y, w, h, false);
        if (ret != 0) {
            drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
            return -EIO;
        }
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
    return 0;
}

static int virtio_gpu_set_plane(drm_device_t *drm_dev,
                                struct drm_mode_set_plane *plane_cmd) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !plane_cmd) {
        return -EINVAL;
    }

    drm_plane_t *plane =
        drm_plane_get(&gpu_dev->resource_mgr, plane_cmd->plane_id);
    if (!plane) {
        return -ENOENT;
    }

    uint32_t target_crtc_id =
        plane_cmd->crtc_id ? plane_cmd->crtc_id : plane->crtc_id;
    int ret = 0;

    if (plane_cmd->fb_id == 0) {
        if (target_crtc_id == 0) {
            plane->fb_id = 0;
            drm_plane_free(&gpu_dev->resource_mgr, plane->id);
            return 0;
        }

        uint32_t scanout_id = 0;
        uint32_t display_idx = 0;
        ret = virtio_gpu_get_scanout_from_crtc(gpu_dev, target_crtc_id,
                                               &scanout_id, &display_idx);
        if (ret != 0) {
            drm_plane_free(&gpu_dev->resource_mgr, plane->id);
            return ret;
        }

        ret = virtio_gpu_set_scanout(gpu_dev, scanout_id, 0, 0, 0, 0, 0);
        if (ret == 0) {
            plane->crtc_id = target_crtc_id;
            plane->fb_id = 0;
            if (gpu_dev->crtcs[display_idx]) {
                gpu_dev->crtcs[display_idx]->fb_id = 0;
            }
        }
        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
        return ret ? -EIO : 0;
    }

    drm_framebuffer_t *drm_fb = NULL;
    struct virtio_gpu_framebuffer *fb = NULL;
    ret = virtio_gpu_get_fb_from_fb_id(gpu_dev, plane_cmd->fb_id, &drm_fb, &fb,
                                       NULL);
    if (ret != 0) {
        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
        return ret;
    }

    if (target_crtc_id == 0) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
        return -EINVAL;
    }

    uint32_t scanout_id = 0;
    uint32_t display_idx = 0;
    ret = virtio_gpu_get_scanout_from_crtc(gpu_dev, target_crtc_id, &scanout_id,
                                           &display_idx);
    if (ret != 0) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
        drm_plane_free(&gpu_dev->resource_mgr, plane->id);
        return ret;
    }

    uint32_t src_x = plane_cmd->src_x >> 16;
    uint32_t src_y = plane_cmd->src_y >> 16;
    uint32_t src_w = plane_cmd->src_w >> 16;
    uint32_t src_h = plane_cmd->src_h >> 16;
    if (src_w == 0) {
        src_w = plane_cmd->crtc_w ? plane_cmd->crtc_w : fb->width;
    }
    if (src_h == 0) {
        src_h = plane_cmd->crtc_h ? plane_cmd->crtc_h : fb->height;
    }

    ret = virtio_gpu_present_region(gpu_dev, fb, scanout_id, src_x, src_y,
                                    src_w, src_h, true);
    if (ret == 0) {
        plane->crtc_id = target_crtc_id;
        plane->fb_id = plane_cmd->fb_id;
        if (gpu_dev->crtcs[display_idx]) {
            gpu_dev->crtcs[display_idx]->fb_id = plane_cmd->fb_id;
            gpu_dev->crtcs[display_idx]->x = plane_cmd->crtc_x;
            gpu_dev->crtcs[display_idx]->y = plane_cmd->crtc_y;
            gpu_dev->crtcs[display_idx]->w = plane_cmd->crtc_w;
            gpu_dev->crtcs[display_idx]->h = plane_cmd->crtc_h;
            gpu_dev->crtcs[display_idx]->mode_valid = 1;
        }
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
    drm_plane_free(&gpu_dev->resource_mgr, plane->id);
    return ret ? -EIO : 0;
}

static int virtio_gpu_set_cursor(drm_device_t *drm_dev,
                                 struct drm_mode_cursor *cursor) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !cursor) {
        return -EINVAL;
    }

    if (cursor->handle == 0) {
        return virtio_gpu_update_cursor(gpu_dev, 0, cursor->x, cursor->y, 0, 0);
    }

    uint32_t idx = 0;
    if (!virtio_gpu_handle_to_index(cursor->handle, &idx) ||
        gpu_dev->framebuffers[idx].resource_id == 0) {
        return -EINVAL;
    }

    uint32_t resource_id = gpu_dev->framebuffers[idx].resource_id;
    int ret = virtio_gpu_update_cursor(gpu_dev, resource_id, cursor->x,
                                       cursor->y, 0, 0);
    if (ret != 0) {
        return -EIO;
    }

    return virtio_gpu_move_cursor(gpu_dev, resource_id, cursor->x, cursor->y);
}

static int virtio_gpu_set_crtc(drm_device_t *drm_dev,
                               struct drm_mode_crtc *crtc) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !crtc) {
        return -EINVAL;
    }

    uint32_t scanout_id = 0;
    uint32_t display_idx = 0;
    int ret = virtio_gpu_get_scanout_from_crtc(gpu_dev, crtc->crtc_id,
                                               &scanout_id, &display_idx);
    if (ret != 0) {
        return ret;
    }

    if (crtc->fb_id == 0) {
        ret = virtio_gpu_set_scanout(gpu_dev, scanout_id, 0, 0, 0, 0, 0);
        if (ret == 0) {
            gpu_dev->crtcs[display_idx]->fb_id = 0;
            gpu_dev->crtcs[display_idx]->mode_valid = 0;
            if (gpu_dev->planes[display_idx]) {
                gpu_dev->planes[display_idx]->fb_id = 0;
            }
        }
        return ret ? -EIO : 0;
    }

    drm_framebuffer_t *drm_fb = NULL;
    struct virtio_gpu_framebuffer *fb = NULL;
    ret =
        virtio_gpu_get_fb_from_fb_id(gpu_dev, crtc->fb_id, &drm_fb, &fb, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = virtio_gpu_present_region(gpu_dev, fb, scanout_id, crtc->x, crtc->y,
                                    crtc->mode.hdisplay, crtc->mode.vdisplay,
                                    true);
    if (ret == 0) {
        gpu_dev->crtcs[display_idx]->fb_id = crtc->fb_id;
        gpu_dev->crtcs[display_idx]->x = crtc->x;
        gpu_dev->crtcs[display_idx]->y = crtc->y;
        gpu_dev->crtcs[display_idx]->w =
            crtc->mode.hdisplay ? crtc->mode.hdisplay : fb->width;
        gpu_dev->crtcs[display_idx]->h =
            crtc->mode.vdisplay ? crtc->mode.vdisplay : fb->height;
        gpu_dev->crtcs[display_idx]->mode_valid = crtc->mode_valid;
        if (gpu_dev->planes[display_idx]) {
            gpu_dev->planes[display_idx]->fb_id = crtc->fb_id;
        }
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, drm_fb->id);
    return ret ? -EIO : 0;
}

static int virtio_gpu_get_connectors(drm_device_t *drm_dev,
                                     drm_connector_t **connectors,
                                     uint32_t *count) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !connectors || !count) {
        return -EINVAL;
    }
    *count = 0;

    for (uint32_t i = 0; i < gpu_dev->num_displays; i++) {
        if (gpu_dev->connectors[i]) {
            connectors[(*count)++] = gpu_dev->connectors[i];
        }
    }

    return 0;
}

static int virtio_gpu_get_crtcs(drm_device_t *drm_dev, drm_crtc_t **crtcs,
                                uint32_t *count) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !crtcs || !count) {
        return -EINVAL;
    }
    *count = 0;

    for (uint32_t i = 0; i < gpu_dev->num_displays; i++) {
        if (gpu_dev->crtcs[i]) {
            crtcs[(*count)++] = gpu_dev->crtcs[i];
        }
    }

    return 0;
}

static int virtio_gpu_get_encoders(drm_device_t *drm_dev,
                                   drm_encoder_t **encoders, uint32_t *count) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !encoders || !count) {
        return -EINVAL;
    }
    *count = 0;

    for (uint32_t i = 0; i < gpu_dev->num_displays; i++) {
        if (gpu_dev->encoders[i]) {
            encoders[(*count)++] = gpu_dev->encoders[i];
        }
    }

    return 0;
}

int virtio_gpu_get_planes(drm_device_t *drm_dev, drm_plane_t **planes,
                          uint32_t *count) {
    virtio_gpu_device_t *device = drm_dev->data;
    if (!device || !planes || !count) {
        return -EINVAL;
    }

    *count = 0;
    for (uint32_t i = 0; i < device->num_displays; i++) {
        if (device->planes[i]) {
            planes[(*count)++] = device->planes[i];
        }
    }

    if (*count == 0) {
        return -ENODEV;
    }

    return 0;
}

// DRM device operations structure
drm_device_op_t virtio_gpu_drm_device_op = {
    .get_display_info = virtio_gpu_get_display_info_drm,
    .get_fb = NULL,
    .create_dumb = virtio_gpu_create_dumb,
    .destroy_dumb = virtio_gpu_destroy_dumb,
    .dirty_fb = virtio_gpu_dirty_fb,
    .add_fb = virtio_gpu_add_fb,
    .add_fb2 = virtio_gpu_add_fb2,
    .set_plane = virtio_gpu_set_plane,
    .atomic_commit = virtio_gpu_atomic_commit,
    .map_dumb = virtio_gpu_map_dumb,
    .set_crtc = virtio_gpu_set_crtc,
    .page_flip = virtio_gpu_page_flip,
    .set_cursor = virtio_gpu_set_cursor,
    .gamma_set = NULL,
    .get_connectors = virtio_gpu_get_connectors,
    .get_crtcs = virtio_gpu_get_crtcs,
    .get_encoders = virtio_gpu_get_encoders,
    .get_planes = virtio_gpu_get_planes,
};

// Virtio GPU initialization
int virtio_gpu_init(virtio_driver_t *driver) {
    uint32_t supported_features = VIRTIO_GPU_F_EDID;
    uint32_t features = virtio_begin_init(driver, supported_features);

    // Create control queue
    virtqueue_t *control_queue = virt_queue_new(
        driver, 0, !!(features & (1 << 28)), !!(features & (1 << 29)));
    if (!control_queue) {
        printk("virtio_gpu: Failed to create control queue\n");
        return -1;
    }

    virtqueue_t *cursor_queue = virt_queue_new(
        driver, 1, !!(features & (1 << 28)), !!(features & (1 << 29)));

    virtio_finish_init(driver);

    // Create GPU device structure
    virtio_gpu_device_t *gpu_device = malloc(sizeof(virtio_gpu_device_t));
    memset(gpu_device, 0, sizeof(virtio_gpu_device_t));

    gpu_device->driver = driver;
    gpu_device->control_queue = control_queue;
    gpu_device->cursor_queue = cursor_queue;
    gpu_device->next_resource_id = 1;
    gpu_device->lock = SPIN_INIT;

    // Initialize DRM resource manager
    drm_resource_manager_init(&gpu_device->resource_mgr);

    // Get display information
    if (virtio_gpu_get_display_info(gpu_device) <= 0) {
        printk("virtio_gpu: No displays found\n");
        free(gpu_device);
        return -1;
    }

    uint32_t max_displays = DRM_MAX_CRTCS_PER_DEVICE;
    if (max_displays > DRM_MAX_CONNECTORS_PER_DEVICE) {
        max_displays = DRM_MAX_CONNECTORS_PER_DEVICE;
    }
    if (max_displays > DRM_MAX_ENCODERS_PER_DEVICE) {
        max_displays = DRM_MAX_ENCODERS_PER_DEVICE;
    }
    if (max_displays > DRM_MAX_PLANES_PER_DEVICE) {
        max_displays = DRM_MAX_PLANES_PER_DEVICE;
    }
    if (gpu_device->num_displays > max_displays) {
        printk("virtio_gpu: only exposing %u/%u displays due DRM limits\n",
               max_displays, gpu_device->num_displays);
        gpu_device->num_displays = max_displays;
    }

    // Create DRM resources for each display
    for (uint32_t i = 0; i < gpu_device->num_displays; i++) {
        // Create connector
        gpu_device->connectors[i] = drm_connector_alloc(
            &gpu_device->resource_mgr, DRM_MODE_CONNECTOR_VIRTUAL, gpu_device);
        if (gpu_device->connectors[i]) {
            gpu_device->connectors[i]->connection = DRM_MODE_CONNECTED;
            gpu_device->connectors[i]->mm_width =
                (gpu_device->displays[i].rect.width * 264UL) / 1000UL;
            gpu_device->connectors[i]->mm_height =
                (gpu_device->displays[i].rect.height * 264UL) / 1000UL;
            if (gpu_device->connectors[i]->mm_width == 0) {
                gpu_device->connectors[i]->mm_width = 1;
            }
            if (gpu_device->connectors[i]->mm_height == 0) {
                gpu_device->connectors[i]->mm_height = 1;
            }

            // Add display mode
            gpu_device->connectors[i]->modes =
                malloc(sizeof(struct drm_mode_modeinfo));
            if (gpu_device->connectors[i]->modes) {
                struct drm_mode_modeinfo mode = {
                    .clock = gpu_device->displays[i].rect.width * 60,
                    .hdisplay = gpu_device->displays[i].rect.width,
                    .hsync_start = gpu_device->displays[i].rect.width + 16,
                    .hsync_end = gpu_device->displays[i].rect.width + 16 + 96,
                    .htotal = gpu_device->displays[i].rect.width + 16 + 96 + 48,
                    .vdisplay = gpu_device->displays[i].rect.height,
                    .vsync_start = gpu_device->displays[i].rect.height + 10,
                    .vsync_end = gpu_device->displays[i].rect.height + 10 + 2,
                    .vtotal = gpu_device->displays[i].rect.height + 10 + 2 + 33,
                    .vrefresh = 60,
                };
                sprintf(mode.name, "%dx%d", gpu_device->displays[i].rect.width,
                        gpu_device->displays[i].rect.height);
                memcpy(gpu_device->connectors[i]->modes, &mode,
                       sizeof(struct drm_mode_modeinfo));
                gpu_device->connectors[i]->count_modes = 1;
            }
        }

        // Create CRTC
        gpu_device->crtcs[i] =
            drm_crtc_alloc(&gpu_device->resource_mgr, gpu_device);
        if (gpu_device->crtcs[i]) {
            gpu_device->crtcs[i]->x = 0;
            gpu_device->crtcs[i]->y = 0;
            gpu_device->crtcs[i]->w = gpu_device->displays[i].rect.width;
            gpu_device->crtcs[i]->h = gpu_device->displays[i].rect.height;
            gpu_device->crtcs[i]->mode_valid = 1;
        }

        // Create encoder
        gpu_device->encoders[i] = drm_encoder_alloc(
            &gpu_device->resource_mgr, DRM_MODE_ENCODER_VIRTUAL, gpu_device);

        gpu_device->planes[i] =
            drm_plane_alloc(&gpu_device->resource_mgr, gpu_device);
        if (gpu_device->planes[i]) {
            gpu_device->planes[i]->crtc_id =
                gpu_device->crtcs[i] ? gpu_device->crtcs[i]->id : 0;
            gpu_device->planes[i]->possible_crtcs = 1 << i;
            gpu_device->planes[i]->count_format_types = 2;
            gpu_device->planes[i]->format_types = malloc(
                sizeof(uint32_t) * gpu_device->planes[i]->count_format_types);
            if (gpu_device->planes[i]->format_types) {
                gpu_device->planes[i]->format_types[0] = DRM_FORMAT_BGRX8888;
                gpu_device->planes[i]->format_types[1] = DRM_FORMAT_BGRA8888;
            } else {
                gpu_device->planes[i]->count_format_types = 0;
            }
            gpu_device->planes[i]->plane_type = DRM_PLANE_TYPE_PRIMARY;
        }

        if (gpu_device->encoders[i] && gpu_device->connectors[i] &&
            gpu_device->crtcs[i]) {
            gpu_device->encoders[i]->possible_crtcs = 1 << i;
            gpu_device->connectors[i]->encoder_id = gpu_device->encoders[i]->id;
            gpu_device->connectors[i]->crtc_id = gpu_device->crtcs[i]->id;
            if (gpu_device->planes[i]) {
                gpu_device->planes[i]->crtc_id = gpu_device->crtcs[i]->id;
            }
        }
    }

    memset(gpu_device->framebuffers, 0, sizeof(gpu_device->framebuffers));

    // Register with DRM subsystem
    drm_regist_pci_dev(gpu_device, &virtio_gpu_drm_device_op,
                       ((virtio_pci_device_t *)driver->data)->pci_dev);

    // Add to global device array
    if (virtio_gpu_devices_count < MAX_VIRTIO_GPU_DEVICES) {
        virtio_gpu_devices[virtio_gpu_devices_count++] = gpu_device;
    } else {
        printk("virtio_gpu: Maximum number of GPU devices reached\n");
        free(gpu_device);
        return -1;
    }

    printk("virtio_gpu: Initialized GPU with %d displays\n",
           gpu_device->num_displays);

    return 0;
}
