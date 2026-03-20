#include <dev/drm/plainfb.h>
#include <dev/drm/drm_ioctl.h>
#include <dev/drm/drm_core.h>
#include <dev/drm/drm.h>
#include <fs/vfs/vfs.h>
#include <fs/sys.h>

static bool plainfb_handle_to_index(uint32_t handle, uint32_t *idx) {
    if (handle == 0 || handle > 32 || !idx) {
        return false;
    }

    *idx = handle - 1;
    return true;
}

static drm_encoder_t *
plainfb_encoder_for_connector(plainfb_device_t *gpu_dev,
                              drm_connector_t *connector) {
    if (!gpu_dev || !connector || connector->encoder_id == 0) {
        return NULL;
    }

    for (uint32_t i = 0; i < 16; i++) {
        if (gpu_dev->encoders[i] &&
            gpu_dev->encoders[i]->id == connector->encoder_id) {
            return gpu_dev->encoders[i];
        }
    }

    return NULL;
}

static void plainfb_bind_connector_crtc(plainfb_device_t *gpu_dev,
                                        drm_connector_t *connector,
                                        uint32_t crtc_id) {
    if (!gpu_dev || !connector) {
        return;
    }

    connector->crtc_id = crtc_id;

    drm_encoder_t *encoder = plainfb_encoder_for_connector(gpu_dev, connector);
    if (encoder) {
        encoder->crtc_id = crtc_id;
    }
}

static int plainfb_present_dumbbuffer(plainfb_device_t *gpu_dev, uint32_t idx,
                                      uint32_t x, uint32_t y, uint32_t width,
                                      uint32_t height) {
    if (!gpu_dev || !gpu_dev->framebuffer || idx >= 32 ||
        !gpu_dev->dumbbuffers[idx].used) {
        return -EINVAL;
    }

    uint32_t bytes_per_pixel = gpu_dev->framebuffer->bpp / 8;
    if (bytes_per_pixel == 0) {
        return -EINVAL;
    }

    uint32_t src_pitch = gpu_dev->dumbbuffers[idx].pitch;
    uint32_t src_width = gpu_dev->dumbbuffers[idx].width;
    uint32_t src_height = gpu_dev->dumbbuffers[idx].height;
    uint32_t dst_pitch = (uint32_t)gpu_dev->framebuffer->pitch;
    uint32_t dst_width = (uint32_t)gpu_dev->framebuffer->width;
    uint32_t dst_height = (uint32_t)gpu_dev->framebuffer->height;

    if (x >= src_width || y >= src_height || x >= dst_width ||
        y >= dst_height) {
        return 0;
    }

    if (width == 0) {
        width = src_width;
    }
    if (height == 0) {
        height = src_height;
    }

    uint32_t max_src_width = src_pitch / bytes_per_pixel;
    uint32_t max_dst_width = dst_pitch / bytes_per_pixel;

    width = MIN(width, src_width - x);
    width = MIN(width, dst_width - x);
    width = MIN(width, max_src_width - x);
    width = MIN(width, max_dst_width - x);
    height = MIN(height, src_height - y);
    height = MIN(height, dst_height - y);

    if (width == 0 || height == 0) {
        return 0;
    }

    size_t row_bytes = (size_t)width * bytes_per_pixel;
    uint8_t *src =
        (uint8_t *)(uintptr_t)phys_to_virt(gpu_dev->dumbbuffers[idx].addr) +
        ((size_t)y * src_pitch) + ((size_t)x * bytes_per_pixel);
    uint8_t *dst = (uint8_t *)(uintptr_t)gpu_dev->framebuffer->address +
                   ((size_t)y * dst_pitch) + ((size_t)x * bytes_per_pixel);

    if (x == 0 && row_bytes == src_pitch && row_bytes == dst_pitch) {
        fast_copy_16(dst, src, row_bytes * (size_t)height);
        return 0;
    }

    for (uint32_t row = 0; row < height; row++) {
        fast_copy_16(dst, src, row_bytes);
        src += src_pitch;
        dst += dst_pitch;
    }

    return 0;
}

int plainfb_get_display_info(drm_device_t *drm_dev, uint32_t *width,
                             uint32_t *height, uint32_t *bpp) {
    plainfb_device_t *dev = drm_dev->data;
    if (dev && dev->framebuffer) {
        *width = dev->framebuffer->width;
        *height = dev->framebuffer->height;
        *bpp = dev->framebuffer->bpp;
        return 0;
    }
    return -ENODEV;
}

int plainfb_create_dumb(drm_device_t *drm_dev,
                        struct drm_mode_create_dumb *args, fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        return -ENODEV;
    }

    if (args->width == 0 || args->height == 0) {
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

    // Find free framebuffer slot
    for (uint32_t i = 0; i < 32; i++) {
        if (!gpu_dev->dumbbuffers[i].used) {
            gpu_dev->dumbbuffers[i].used = true;
            gpu_dev->dumbbuffers[i].width = args->width;
            gpu_dev->dumbbuffers[i].height = args->height;
            gpu_dev->dumbbuffers[i].refcount = 1;
            gpu_dev->dumbbuffers[i].direct_backed = false;

            gpu_dev->dumbbuffers[i].pitch = args->pitch;

            // Allocate memory for framebuffer
            gpu_dev->dumbbuffers[i].addr = alloc_frames(
                (args->size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);
            memset((void *)phys_to_virt(gpu_dev->dumbbuffers[i].addr), 0,
                   (args->size + DEFAULT_PAGE_SIZE - 1) &
                       ~(DEFAULT_PAGE_SIZE - 1));

            args->handle = i + 1;
            return 0;
        }
    }

    return -ENOSPC;
}

static int plainfb_destroy_dumb(drm_device_t *drm_dev, uint32_t handle,
                                fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        return -ENODEV;
    }

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(handle, &idx) ||
        !gpu_dev->dumbbuffers[idx].used) {
        return -EINVAL;
    }

    if (--gpu_dev->dumbbuffers[idx].refcount == 0) {
        free_frames(gpu_dev->dumbbuffers[idx].addr,
                    (gpu_dev->dumbbuffers[idx].pitch *
                         gpu_dev->dumbbuffers[idx].height +
                     DEFAULT_PAGE_SIZE - 1) /
                        DEFAULT_PAGE_SIZE);
        gpu_dev->dumbbuffers[idx].direct_backed = false;
        gpu_dev->dumbbuffers[idx].used = false;
    }

    return 0;
}

static int plainfb_add_fb(drm_device_t *drm_dev, struct drm_mode_fb_cmd *fb_cmd,
                          fd_t *fd) {
    (void)fd;
    plainfb_device_t *device = drm_dev->data;
    if (!device) {
        return -ENODEV;
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
    fb->format = DRM_FORMAT_XRGB8888;

    fb_cmd->fb_id = fb->id;

    return 0;
}

static int plainfb_dirty_fb(drm_device_t *drm_dev,
                            struct drm_mode_fb_dirty_cmd *cmd, fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !gpu_dev->framebuffer || !cmd ||
        (cmd->flags & ~DRM_MODE_FB_DIRTY_FLAGS)) {
        return -EINVAL;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_get(&gpu_dev->resource_mgr, cmd->fb_id);
    if (!fb) {
        return -ENOENT;
    }

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(fb->handle, &idx) ||
        !gpu_dev->dumbbuffers[idx].used) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
        return -EINVAL;
    }

    int ret = 0;
    if (cmd->num_clips == 0 || cmd->clips_ptr == 0) {
        ret = plainfb_present_dumbbuffer(gpu_dev, idx, 0, 0, 0, 0);
    } else {
        uint32_t clips_count = MIN(cmd->num_clips, DRM_MODE_FB_DIRTY_MAX_CLIPS);
        drm_clip_rect_t *clips = (drm_clip_rect_t *)(uintptr_t)cmd->clips_ptr;
        uint32_t bbox_x1 = UINT32_MAX;
        uint32_t bbox_y1 = UINT32_MAX;
        uint32_t bbox_x2 = 0;
        uint32_t bbox_y2 = 0;
        uint64_t clip_area = 0;
        uint32_t valid_clips = 0;

        for (uint32_t i = 0; i < clips_count; i++) {
            uint32_t x1 = clips[i].x1;
            uint32_t y1 = clips[i].y1;
            uint32_t x2 = clips[i].x2;
            uint32_t y2 = clips[i].y2;

            if (x2 <= x1 || y2 <= y1) {
                continue;
            }

            bbox_x1 = MIN(bbox_x1, x1);
            bbox_y1 = MIN(bbox_y1, y1);
            bbox_x2 = MAX(bbox_x2, x2);
            bbox_y2 = MAX(bbox_y2, y2);
            clip_area += (uint64_t)(x2 - x1) * (uint64_t)(y2 - y1);
            valid_clips++;
        }

        if (valid_clips > 1 && bbox_x2 > bbox_x1 && bbox_y2 > bbox_y1) {
            uint64_t bbox_area =
                (uint64_t)(bbox_x2 - bbox_x1) * (uint64_t)(bbox_y2 - bbox_y1);
            if (valid_clips > 8 || bbox_area <= clip_area * 2) {
                ret = plainfb_present_dumbbuffer(gpu_dev, idx, bbox_x1, bbox_y1,
                                                 bbox_x2 - bbox_x1,
                                                 bbox_y2 - bbox_y1);
                drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
                return ret;
            }
        }

        for (uint32_t i = 0; i < clips_count; i++) {
            uint32_t x = clips[i].x1;
            uint32_t y = clips[i].y1;
            uint32_t w =
                clips[i].x2 > clips[i].x1 ? clips[i].x2 - clips[i].x1 : 0;
            uint32_t h =
                clips[i].y2 > clips[i].y1 ? clips[i].y2 - clips[i].y1 : 0;
            if (w == 0 || h == 0) {
                continue;
            }

            ret = plainfb_present_dumbbuffer(gpu_dev, idx, x, y, w, h);
            if (ret != 0) {
                break;
            }
        }
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
    return ret;
}

static int plainfb_add_fb2(drm_device_t *drm_dev,
                           struct drm_mode_fb_cmd2 *fb_cmd, fd_t *fd) {
    (void)fd;
    plainfb_device_t *device = drm_dev->data;
    if (!device) {
        return -ENODEV;
    }

    if (fb_cmd->handles[0] == 0 || fb_cmd->width == 0 || fb_cmd->height == 0) {
        return -EINVAL;
    }

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(fb_cmd->handles[0], &idx) ||
        !device->dumbbuffers[idx].used) {
        return -EINVAL;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&device->resource_mgr, device);
    if (!fb) {
        return -ENOMEM;
    }

    fb->width = fb_cmd->width;
    fb->height = fb_cmd->height;
    fb->pitch = fb_cmd->pitches[0] ? fb_cmd->pitches[0]
                                   : device->dumbbuffers[idx].pitch;
    fb->bpp = 32;
    fb->depth = (fb_cmd->pixel_format == DRM_FORMAT_ARGB8888 ||
                 fb_cmd->pixel_format == DRM_FORMAT_ABGR8888 ||
                 fb_cmd->pixel_format == DRM_FORMAT_RGBA8888 ||
                 fb_cmd->pixel_format == DRM_FORMAT_BGRA8888)
                    ? 32
                    : 24;
    fb->handle = fb_cmd->handles[0];
    fb->format = fb_cmd->pixel_format;
    fb->modifier = fb_cmd->modifier[0];

    fb_cmd->fb_id = fb->id;

    return 0;
}

int plainfb_atomic_commit(drm_device_t *drm_dev, struct drm_mode_atomic *atomic,
                          fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !gpu_dev->framebuffer || !atomic) {
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
    uint32_t committed_fb_id = 0;
    bool has_committed_fb = false;
    uint32_t stale_fb_ids[DRM_MAX_PLANES_PER_DEVICE] = {0};
    uint32_t stale_fb_count = 0;

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
                // Immutable: userspace may query it, but must not set it.
                if (value != plane->plane_type) {
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
                    drm_framebuffer_t *fb = drm_framebuffer_get(
                        &gpu_dev->resource_mgr, (uint32_t)value);
                    if (!fb) {
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
                    if (!plainfb_handle_to_index(fb->handle, &fb_idx) ||
                        !gpu_dev->dumbbuffers[fb_idx].used) {
                        drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
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

                    drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
                }

                if (!test_only) {
                    if (plane->fb_id != 0 && plane->fb_id != (uint32_t)value &&
                        stale_fb_count < DRM_MAX_PLANES_PER_DEVICE) {
                        stale_fb_ids[stale_fb_count++] = plane->fb_id;
                    }
                    plane->fb_id = (uint32_t)value;
                }

                committed_fb_id = (uint32_t)value;
                has_committed_fb = (value != 0);
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

            case DRM_CRTC_ACTIVE_PROP_ID:
                if (crtc && !test_only) {
                    crtc->mode_valid = (value != 0);
                }
                break;

            case DRM_CRTC_MODE_ID_PROP_ID:
                if (crtc && !test_only) {
                    if (value == 0) {
                        crtc->mode_valid = 0;
                        memset(&crtc->mode, 0, sizeof(crtc->mode));
                    } else {
                        struct drm_mode_modeinfo mode;
                        memset(&mode, 0, sizeof(mode));

                        int ret = drm_property_get_modeinfo_from_blob(
                            drm_dev, (uint32_t)value, &mode);
                        if (ret != 0 || mode.hdisplay == 0 ||
                            mode.vdisplay == 0) {
                            if (connector) {
                                drm_connector_free(&gpu_dev->resource_mgr,
                                                   connector->id);
                            }
                            if (crtc) {
                                drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);
                            }
                            if (plane) {
                                drm_plane_free(&gpu_dev->resource_mgr,
                                               plane->id);
                            }
                            return ret != 0 ? ret : -EINVAL;
                        }

                        crtc->mode = mode;
                        crtc->mode_valid = 1;
                        crtc->w = mode.hdisplay;
                        crtc->h = mode.vdisplay;
                    }
                }
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
                    plainfb_bind_connector_crtc(gpu_dev, connector,
                                                (uint32_t)value);
                }
                break;

            default:
                // Accept unknown properties to stay permissive for userspace.
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

    if (test_only || !has_committed_fb) {
        return 0;
    }

    drm_framebuffer_t *scanout_fb =
        drm_framebuffer_get(&gpu_dev->resource_mgr, committed_fb_id);
    if (!scanout_fb) {
        return -ENOENT;
    }

    uint32_t scanout_idx = 0;
    if (!plainfb_handle_to_index(scanout_fb->handle, &scanout_idx) ||
        !gpu_dev->dumbbuffers[scanout_idx].used) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, scanout_fb->id);
        return -EINVAL;
    }

    int ret = plainfb_present_dumbbuffer(gpu_dev, scanout_idx, 0, 0, 0, 0);
    if (ret != 0) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, scanout_fb->id);
        return ret;
    }

    drm_framebuffer_free(&gpu_dev->resource_mgr, scanout_fb->id);

    if (atomic->flags & DRM_MODE_PAGE_FLIP_EVENT) {
        ret = drm_defer_event(drm_dev, DRM_EVENT_FLIP_COMPLETE,
                              atomic->user_data);
        if (ret < 0) {
            return ret;
        }
    }

    for (uint32_t i = 0; i < stale_fb_count; i++) {
        drm_framebuffer_cleanup_closed(drm_dev, stale_fb_ids[i]);
    }

    return 0;
}

int plainfb_map_dumb(drm_device_t *drm_dev, struct drm_mode_map_dumb *args,
                     fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        return -ENODEV;
    }

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(args->handle, &idx) ||
        !gpu_dev->dumbbuffers[idx].used) {
        return -EINVAL;
    }

    args->offset = gpu_dev->dumbbuffers[idx].addr;

    return 0;
}

static int plainfb_set_crtc(drm_device_t *drm_dev, struct drm_mode_crtc *crtc,
                            fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !gpu_dev->framebuffer || !crtc || crtc->fb_id == 0) {
        return 0;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_get(&gpu_dev->resource_mgr, crtc->fb_id);
    if (!fb) {
        return -ENOENT;
    }

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(fb->handle, &idx) ||
        !gpu_dev->dumbbuffers[idx].used) {
        drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
        return -EINVAL;
    }

    int ret = plainfb_present_dumbbuffer(gpu_dev, idx, 0, 0, 0, 0);
    drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);
    return ret;
}

static int plainfb_page_flip(drm_device_t *drm_dev,
                             struct drm_mode_crtc_page_flip *flip, fd_t *fd) {
    (void)fd;
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev || !gpu_dev->framebuffer) {
        return -ENODEV;
    }

    drm_crtc_t *crtc = drm_crtc_get(&gpu_dev->resource_mgr, flip->crtc_id);
    if (!crtc) {
        return -EINVAL;
    }
    uint32_t old_fb_id = crtc->fb_id;
    crtc->fb_id = flip->fb_id;
    drm_crtc_free(&gpu_dev->resource_mgr, crtc->id);

    drm_framebuffer_t *fb =
        drm_framebuffer_get(&gpu_dev->resource_mgr, flip->fb_id);
    if (!fb) {
        return -EINVAL;
    }

    uint32_t handle = fb->handle;
    drm_framebuffer_free(&gpu_dev->resource_mgr, fb->id);

    uint32_t idx = 0;
    if (!plainfb_handle_to_index(handle, &idx) ||
        !gpu_dev->dumbbuffers[idx].used) {
        return -EINVAL;
    }

    int ret = plainfb_present_dumbbuffer(gpu_dev, idx, 0, 0, 0, 0);
    if (ret != 0) {
        return ret;
    }

    if (flip->flags & DRM_MODE_PAGE_FLIP_EVENT) {
        ret =
            drm_defer_event(drm_dev, DRM_EVENT_FLIP_COMPLETE, flip->user_data);
        if (ret < 0) {
            return ret;
        }
    }

    if (old_fb_id != 0 && old_fb_id != flip->fb_id) {
        drm_framebuffer_cleanup_closed(drm_dev, old_fb_id);
    }

    return 0;
}

static int plainfb_get_connectors(drm_device_t *drm_dev,
                                  drm_connector_t **connectors,
                                  uint32_t *count) {
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        *count = 0;
        return -ENODEV;
    }

    *count = 0;

    for (uint32_t i = 0; i < 1; i++) {
        if (gpu_dev->connectors[i]) {
            connectors[(*count)++] = gpu_dev->connectors[i];
        }
    }

    return 0;
}

static int plainfb_get_crtcs(drm_device_t *drm_dev, drm_crtc_t **crtcs,
                             uint32_t *count) {
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        *count = 0;
        return -ENODEV;
    }

    *count = 0;

    for (uint32_t i = 0; i < 1; i++) {
        if (gpu_dev->crtcs[i]) {
            crtcs[(*count)++] = gpu_dev->crtcs[i];
        }
    }

    return 0;
}

static int plainfb_get_encoders(drm_device_t *drm_dev, drm_encoder_t **encoders,
                                uint32_t *count) {
    plainfb_device_t *gpu_dev = drm_dev->data;
    if (!gpu_dev) {
        *count = 0;
        return -ENODEV;
    }

    *count = 0;

    for (uint32_t i = 0; i < 1; i++) {
        if (gpu_dev->encoders[i]) {
            encoders[(*count)++] = gpu_dev->encoders[i];
        }
    }

    return 0;
}

int plainfb_get_planes(drm_device_t *drm_dev, drm_plane_t **planes,
                       uint32_t *count) {
    plainfb_device_t *device = drm_dev->data;
    if (!device) {
        *count = 0;
        return -ENODEV;
    }

    *count = 1;
    planes[0] = drm_plane_alloc(&device->resource_mgr, drm_dev->data);
    if (!planes[0]) {
        *count = 0;
        return -ENOMEM;
    }

    planes[0]->crtc_id = device->crtcs[0] ? device->crtcs[0]->id : 0;
    planes[0]->fb_id = device->crtcs[0] ? device->crtcs[0]->fb_id : 0;
    planes[0]->possible_crtcs = 1;
    planes[0]->count_format_types = 4;
    planes[0]->format_types =
        malloc(sizeof(uint32_t) * planes[0]->count_format_types);
    if (planes[0]->format_types) {
        planes[0]->format_types[0] = DRM_FORMAT_XRGB8888;
        planes[0]->format_types[1] = DRM_FORMAT_ARGB8888;
        planes[0]->format_types[2] = DRM_FORMAT_XBGR8888;
        planes[0]->format_types[3] = DRM_FORMAT_ABGR8888;
    }
    planes[0]->plane_type = DRM_PLANE_TYPE_PRIMARY;
    return 0;
}

// DRM device operations structure
drm_device_op_t plainfb_drm_device_op = {
    .supports_render_node = false,
    .get_display_info = plainfb_get_display_info,
    .get_fb = NULL,
    .create_dumb = plainfb_create_dumb,
    .destroy_dumb = plainfb_destroy_dumb,
    .dirty_fb = plainfb_dirty_fb,
    .add_fb = plainfb_add_fb,
    .add_fb2 = plainfb_add_fb2,
    .set_plane = NULL,
    .atomic_commit = plainfb_atomic_commit,
    .map_dumb = plainfb_map_dumb,
    .set_crtc = plainfb_set_crtc,
    .page_flip = plainfb_page_flip,
    .set_cursor = NULL,
    .gamma_set = NULL,
    .get_connectors = plainfb_get_connectors,
    .get_crtcs = plainfb_get_crtcs,
    .get_encoders = plainfb_get_encoders,
    .get_planes = plainfb_get_planes,
};

void drm_plainfb_init() {
    boot_framebuffer_t *fb = boot_get_framebuffer();
    if (!fb) {
        printk("plainfb: No framebuffer found\n");
        return;
    }

    // Create GPU device structure
    plainfb_device_t *gpu_device = malloc(sizeof(plainfb_device_t));
    if (!gpu_device) {
        printk("plainfb: Failed to allocate device\n");
        return;
    }

    memset(gpu_device, 0, sizeof(plainfb_device_t));
    gpu_device->framebuffer = fb;

    // Initialize DRM resource manager
    drm_resource_manager_init(&gpu_device->resource_mgr);

    int i = 0;
    // Create connector
    gpu_device->connectors[i] = drm_connector_alloc(
        &gpu_device->resource_mgr, DRM_MODE_CONNECTOR_VIRTUAL, gpu_device);
    if (gpu_device->connectors[i]) {
        gpu_device->connectors[i]->connection = DRM_MODE_CONNECTED;
        gpu_device->connectors[i]->mm_width = (fb->width * 264UL) / 1000UL;
        gpu_device->connectors[i]->mm_height = (fb->height * 264UL) / 1000UL;
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
                .clock = fb->width * HZ,
                .hdisplay = fb->width,
                .hsync_start = fb->width + 16,
                .hsync_end = fb->width + 16 + 96,
                .htotal = fb->width + 16 + 96 + 48,
                .vdisplay = fb->height,
                .vsync_start = fb->height + 10,
                .vsync_end = fb->height + 10 + 2,
                .vtotal = fb->height + 10 + 2 + 33,
                .vrefresh = HZ,
            };
            sprintf(mode.name, "%dx%d", fb->width, fb->height);
            memcpy(gpu_device->connectors[i]->modes, &mode,
                   sizeof(struct drm_mode_modeinfo));
            gpu_device->connectors[i]->count_modes = 1;
        }
    }

    // Create CRTC
    gpu_device->crtcs[i] =
        drm_crtc_alloc(&gpu_device->resource_mgr, gpu_device);
    gpu_device->crtcs[i]->x = 0;
    gpu_device->crtcs[i]->y = 0;
    gpu_device->crtcs[i]->w = fb->width;
    gpu_device->crtcs[i]->h = fb->height;
    if (gpu_device->connectors[i] && gpu_device->connectors[i]->modes &&
        gpu_device->connectors[i]->count_modes > 0) {
        gpu_device->crtcs[i]->mode = gpu_device->connectors[i]->modes[0];
        gpu_device->crtcs[i]->mode_valid = 1;
    }

    // Create encoder
    gpu_device->encoders[i] = drm_encoder_alloc(
        &gpu_device->resource_mgr, DRM_MODE_ENCODER_VIRTUAL, gpu_device);

    if (gpu_device->encoders[i] && gpu_device->connectors[i] &&
        gpu_device->crtcs[i]) {
        gpu_device->encoders[i]->possible_crtcs = 1 << i;
        gpu_device->encoders[i]->crtc_id = gpu_device->crtcs[i]->id;
        gpu_device->connectors[i]->encoder_id = gpu_device->encoders[i]->id;
        plainfb_bind_connector_crtc(gpu_device, gpu_device->connectors[i],
                                    gpu_device->crtcs[i]->id);
    }

    memset(gpu_device->dumbbuffers, 0, sizeof(gpu_device->dumbbuffers));

    pci_device_t *vga_pci_devices[8];
    uint32_t count;
    pci_find_class(vga_pci_devices, &count, 0x00030000);

    if (count > 0) {
        // Register with DRM subsystem using PCI device
        drm_device_t *drm_dev = drm_regist_pci_dev(
            gpu_device, &plainfb_drm_device_op, vga_pci_devices[0]);
        if (drm_dev) {
            const char *driver_name = "simpledrm";
            if (vga_pci_devices[0]->vendor_id == 0x1234 &&
                vga_pci_devices[0]->device_id == 0x1111) {
                driver_name = "bochs-drm";
            }

            drm_device_set_driver_info(drm_dev, driver_name, "20260310",
                                       "NaOS plain framebuffer DRM");

            char driver_root[128];
            sprintf(driver_root, "/sys/bus/pci/drivers/%s", driver_name);
            sysfs_ensure_dir(driver_root);

            char pci_device_path[128];
            sprintf(pci_device_path, "/sys/bus/pci/devices/%04x:%02x:%02x.%u",
                    vga_pci_devices[0]->segment, vga_pci_devices[0]->bus,
                    vga_pci_devices[0]->slot, vga_pci_devices[0]->func);

            char driver_link_path[192];
            sprintf(driver_link_path, "%s/driver", pci_device_path);
            sysfs_symlink_path(driver_link_path, driver_root);

            char reverse_link_path[192];
            sprintf(reverse_link_path, "%s/%04x:%02x:%02x.%u", driver_root,
                    vga_pci_devices[0]->segment, vga_pci_devices[0]->bus,
                    vga_pci_devices[0]->slot, vga_pci_devices[0]->func);
            sysfs_symlink_path(reverse_link_path, pci_device_path);

            char pci_uevent_path[192];
            sprintf(pci_uevent_path, "%s/uevent", pci_device_path);
            vfs_node_t *pci_uevent = sysfs_open_node(pci_uevent_path, 0);
            if (pci_uevent) {
                char uevent_content[256];
                sprintf(uevent_content,
                        "DRIVER=%s\nPCI_SLOT_NAME=%04x:%02x:%02x.%u\n",
                        driver_name, vga_pci_devices[0]->segment,
                        vga_pci_devices[0]->bus, vga_pci_devices[0]->slot,
                        vga_pci_devices[0]->func);
                vfs_write(pci_uevent, uevent_content, 0,
                          strlen(uevent_content));
            }
        }
    };
}
