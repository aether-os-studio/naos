#include "gpu.h"
#include "pci.h"
#include <libs/aether/drm.h>
#include <libs/aether/mm.h>
#include <libs/klibc.h>

virtio_gpu_device_t *virtio_gpu_devices[MAX_VIRTIO_GPU_DEVICES];
uint32_t virtio_gpu_devices_count = 0;

// Send control command to GPU
static int virtio_gpu_send_command(virtio_gpu_device_t *gpu_dev, void *cmd,
                                   size_t cmd_size, void *resp,
                                   size_t resp_size) {
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

    uint16_t desc_idx =
        virt_queue_add_buf(gpu_dev->control_queue, bufs, 2, writable);
    if (desc_idx == 0xFFFF) {
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
    for (int i = 0; i < 16; i++) {
        if (resp.displays[i].enabled) {
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
        .height = height};

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

// Set scanout (display resource on screen)
int virtio_gpu_set_scanout(virtio_gpu_device_t *gpu_dev, uint32_t scanout_id,
                           uint32_t resource_id, uint32_t width,
                           uint32_t height, uint32_t x, uint32_t y) {
    virtio_gpu_set_scanout_t cmd = {.hdr = {.type = VIRTIO_GPU_CMD_SET_SCANOUT,
                                            .flags = 0,
                                            .fence_id = 0,
                                            .ctx_id = 0,
                                            .padding = 0},
                                    .scanout_id = scanout_id,
                                    .resource_id = resource_id,
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

// DRM device operations
static int virtio_gpu_get_display_info_drm(drm_device_t *drm_dev,
                                           uint32_t *width, uint32_t *height,
                                           uint32_t *bpp) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
    if (gpu_dev->num_displays > 0) {
        *width = gpu_dev->displays[0].rect.width;
        *height = gpu_dev->displays[0].rect.height;
        *bpp = 32; // Virtio GPU typically uses 32bpp
        return 0;
    }
    return -ENODEV;
}

static int virtio_gpu_create_dumb(drm_device_t *drm_dev,
                                  struct drm_mode_create_dumb *args) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;

    args->pitch = args->width * (args->bpp / 8);
    args->size = args->height * args->pitch;

    // Find free framebuffer slot
    for (uint32_t i = 0; i < 32; i++) {
        if (gpu_dev->framebuffers[i].resource_id == 0) {
            virtio_gpu_create_resource(gpu_dev, RESOURCE_ID_FB,
                                       VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
                                       args->width, args->height);
            gpu_dev->framebuffers[i].resource_id = RESOURCE_ID_FB;
            gpu_dev->framebuffers[i].width = args->width;
            gpu_dev->framebuffers[i].height = args->height;
            gpu_dev->framebuffers[i].pitch = args->pitch;
            gpu_dev->framebuffers[i].format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
            gpu_dev->framebuffers[i].refcount = 1;

            // Allocate memory for framebuffer
            gpu_dev->framebuffers[i].addr = alloc_frames(
                (args->size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);

            args->handle = i;
            return 0;
        }
    }

    return -ENOSPC;
}

static int virtio_gpu_destroy_dumb(drm_device_t *drm_dev, uint32_t handle) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;

    if (handle >= 32 || gpu_dev->framebuffers[handle].resource_id == 0) {
        return -EINVAL;
    }

    if (--gpu_dev->framebuffers[handle].refcount == 0) {
        // Free resource and memory
        virtio_gpu_ctrl_hdr_t cmd = {.type = VIRTIO_GPU_CMD_RESOURCE_UNREF,
                                     .flags = 0,
                                     .fence_id = 0,
                                     .ctx_id = 0,
                                     .padding = 0};

        virtio_gpu_ctrl_hdr_t resp;
        memset(&resp, 0, sizeof(resp));

        virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                sizeof(resp));

        // Free memory
        free_frames(gpu_dev->framebuffers[handle].addr,
                    (gpu_dev->framebuffers[handle].pitch *
                         gpu_dev->framebuffers[handle].height +
                     DEFAULT_PAGE_SIZE - 1) /
                        DEFAULT_PAGE_SIZE);

        gpu_dev->framebuffers[handle].resource_id = 0;
    }

    return 0;
}

static int virtio_gpu_map_dumb(drm_device_t *drm_dev,
                               struct drm_mode_map_dumb *args) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;

    if (args->handle >= 32 ||
        gpu_dev->framebuffers[args->handle].resource_id == 0) {
        return -EINVAL;
    }

    args->offset = gpu_dev->framebuffers[args->handle].addr;
    return 0;
}

static int virtio_gpu_add_fb(drm_device_t *drm_dev,
                             struct drm_mode_fb_cmd *fb_cmd) {
    virtio_gpu_device_t *device = drm_dev->data;

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&device->resource_mgr, device);

    fb->width = fb_cmd->width;
    fb->height = fb_cmd->height;
    fb->pitch = fb_cmd->pitch;
    fb->bpp = fb_cmd->bpp;
    fb->depth = fb_cmd->depth;
    fb->handle = fb_cmd->handle;
    fb->format = DRM_FORMAT_BGRA8888;

    fb_cmd->fb_id = fb->id;

    return 0;
}

static int virtio_gpu_add_fb2(drm_device_t *drm_dev,
                              struct drm_mode_fb_cmd2 *fb_cmd) {
    virtio_gpu_device_t *device = drm_dev->data;

    drm_framebuffer_t *fb = drm_framebuffer_alloc(&device->resource_mgr, NULL);
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

    if (flip->crtc_id > gpu_dev->num_displays || flip->fb_id >= 32 ||
        gpu_dev->framebuffers[flip->fb_id - 1].resource_id == 0) {
        return -EINVAL;
    }

    struct virtio_gpu_framebuffer *fb = &gpu_dev->framebuffers[flip->fb_id - 1];

    // Update resource with new data
    virtio_gpu_attach_backing(gpu_dev, fb->resource_id, fb->addr,
                              fb->pitch * fb->height);
    virtio_gpu_transfer_to_host(gpu_dev, fb->resource_id, fb->width, fb->height,
                                0, 0);
    virtio_gpu_set_scanout(gpu_dev, 0, fb->resource_id, fb->width, fb->height,
                           0, 0);
    virtio_gpu_resource_flush(gpu_dev, fb->resource_id, fb->width, fb->height,
                              0, 0);

    // Create flip complete event
    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++) {
        if (!drm_dev->drm_events[i]) {
            drm_dev->drm_events[i] = malloc(sizeof(struct k_drm_event));
            drm_dev->drm_events[i]->type = DRM_EVENT_FLIP_COMPLETE;
            drm_dev->drm_events[i]->user_data = flip->user_data;
            drm_dev->drm_events[i]->timestamp.tv_sec =
                nanoTime() / 1000000000ULL;
            drm_dev->drm_events[i]->timestamp.tv_nsec =
                nanoTime() % 1000000000ULL;
            break;
        }
    }

    return 0;
}

static int virtio_gpu_set_cursor(drm_device_t *drm_dev,
                                 struct drm_mode_cursor *cursor) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;

    if (cursor->handle == 0) {
        // Hide cursor
        return 0;
    }

    // For now, just move cursor - actual cursor resource creation would be more
    // complex
    return virtio_gpu_move_cursor(gpu_dev, 1, cursor->x, cursor->y);
}

static int virtio_gpu_set_crtc(drm_device_t *drm_dev,
                               struct drm_mode_crtc *crtc) {
    // CRTC configuration handled by page flip
    return 0;
}

static int virtio_gpu_get_connectors(drm_device_t *drm_dev,
                                     drm_connector_t **connectors,
                                     uint32_t *count) {
    virtio_gpu_device_t *gpu_dev = drm_dev->data;
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

    *count = 1;
    planes[0] = drm_plane_alloc(&device->resource_mgr, drm_dev->data);
    planes[0]->crtc_id = device->crtcs[0]->id;
    planes[0]->fb_id = device->crtcs[0]->fb_id;
    planes[0]->possible_crtcs = 1;
    planes[0]->count_format_types = 1;
    planes[0]->format_types =
        malloc(sizeof(uint32_t) * planes[0]->count_format_types);
    planes[0]->format_types[0] = DRM_FORMAT_BGRA8888;
    planes[0]->plane_type = DRM_PLANE_TYPE_PRIMARY;
    return 0;
}

// DRM device operations structure
drm_device_op_t virtio_gpu_drm_device_op = {
    .get_display_info = virtio_gpu_get_display_info_drm,
    .get_fb = NULL,
    .create_dumb = virtio_gpu_create_dumb,
    .destroy_dumb = virtio_gpu_destroy_dumb,
    .dirty_fb = NULL,
    .add_fb = virtio_gpu_add_fb,
    .add_fb2 = virtio_gpu_add_fb2,
    .set_plane = NULL,
    .atomic_commit = NULL,
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

    // Create cursor queue if supported
    virtqueue_t *cursor_queue = NULL;
    if (features & VIRTIO_GPU_F_VIRGL) {
        cursor_queue = virt_queue_new(driver, 1, !!(features & (1 << 28)),
                                      !!(features & (1 << 29)));
    }

    virtio_finish_init(driver);

    // Create GPU device structure
    virtio_gpu_device_t *gpu_device = malloc(sizeof(virtio_gpu_device_t));
    memset(gpu_device, 0, sizeof(virtio_gpu_device_t));

    gpu_device->driver = driver;
    gpu_device->control_queue = control_queue;
    gpu_device->cursor_queue = cursor_queue;
    gpu_device->next_resource_id = 1;

    // Initialize DRM resource manager
    drm_resource_manager_init(&gpu_device->resource_mgr);

    // Get display information
    if (virtio_gpu_get_display_info(gpu_device) <= 0) {
        printk("virtio_gpu: No displays found\n");
        free(gpu_device);
        return -1;
    }

    // Create DRM resources for each display
    for (uint32_t i = 0; i < gpu_device->num_displays; i++) {
        // Create connector
        gpu_device->connectors[i] = drm_connector_alloc(
            &gpu_device->resource_mgr, DRM_MODE_CONNECTOR_VIRTUAL, gpu_device);
        if (gpu_device->connectors[i]) {
            gpu_device->connectors[i]->connection = DRM_MODE_CONNECTED;
            gpu_device->connectors[i]->mm_width =
                gpu_device->displays[i].rect.width;
            gpu_device->connectors[i]->mm_height =
                gpu_device->displays[i].rect.height;

            // Add display mode
            gpu_device->connectors[i]->modes =
                malloc(sizeof(struct drm_mode_modeinfo));
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
            memcpy(gpu_device->connectors[i]->modes, &mode,
                   sizeof(struct drm_mode_modeinfo));
            gpu_device->connectors[i]->count_modes = 1;
        }

        // Create CRTC
        gpu_device->crtcs[i] =
            drm_crtc_alloc(&gpu_device->resource_mgr, gpu_device);

        // Create encoder
        gpu_device->encoders[i] = drm_encoder_alloc(
            &gpu_device->resource_mgr, DRM_MODE_ENCODER_VIRTUAL, gpu_device);

        if (gpu_device->encoders[i] && gpu_device->connectors[i] &&
            gpu_device->crtcs[i]) {
            gpu_device->encoders[i]->possible_crtcs = 1 << i;
            gpu_device->connectors[i]->encoder_id = gpu_device->encoders[i]->id;
            gpu_device->connectors[i]->crtc_id = gpu_device->crtcs[i]->id;
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
