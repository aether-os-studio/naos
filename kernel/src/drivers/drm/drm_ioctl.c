/*
 * DRM ioctl implementation
 *
 * This file contains the implementation of DRM ioctl handling functions.
 * It separates the ioctl implementation from the core driver framework.
 */

#include <drivers/drm/drm.h>
#include <drivers/drm/drm_ioctl.h>
#include <drivers/drm/drm_core.h>

/**
 * drm_ioctl_version - Handle DRM_IOCTL_VERSION
 */
int drm_ioctl_version(drm_device_t *dev, void *arg) {
    struct drm_version *version = (struct drm_version *)arg;
    version->version_major = 2;
    version->version_minor = 2;
    version->version_patchlevel = 0;
    version->name_len = sizeof(DRM_NAME);
    if (version->name) {
        if (copy_to_user_str(version->name, DRM_NAME, version->name_len))
            return -EFAULT;
    }
    version->date_len = sizeof(DRM_NAME);
    if (version->date) {
        if (copy_to_user_str(version->date, DRM_NAME, version->date_len))
            return -EFAULT;
    }
    version->desc_len = sizeof(DRM_NAME);
    if (version->desc) {
        if (copy_to_user_str(version->desc, DRM_NAME, version->desc_len))
            return -EFAULT;
    }
    return 0;
}

/**
 * drm_ioctl_get_cap - Handle DRM_IOCTL_GET_CAP
 */
int drm_ioctl_get_cap(drm_device_t *dev, void *arg) {
    struct drm_get_cap *cap = (struct drm_get_cap *)arg;
    switch (cap->capability) {
    case DRM_CAP_DUMB_BUFFER:
        cap->value = 1; // Support dumb buffer
        return 0;
    case DRM_CAP_TIMESTAMP_MONOTONIC:
        cap->value = 1;
        return 0;
    case DRM_CAP_CURSOR_WIDTH:
        cap->value = 32;
        return 0;
    case DRM_CAP_CURSOR_HEIGHT:
        cap->value = 32;
        return 0;
    default:
        printk("drm: Unsupported capability %d\n", cap->capability);
        cap->value = 0;
        return 0;
    }
}

/**
 * drm_ioctl_mode_getresources - Handle DRM_IOCTL_MODE_GETRESOURCES
 */
int drm_ioctl_mode_getresources(drm_device_t *dev, void *arg) {
    struct drm_mode_card_res *res = (struct drm_mode_card_res *)arg;

    // Count available resources
    res->count_fbs = 0;
    res->count_crtcs = 0;
    res->count_connectors = 0;
    res->count_encoders = 0;

    // Count framebuffers
    for (uint32_t i = 0; i < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; i++) {
        if (dev->resource_mgr.framebuffers[i]) {
            res->count_fbs++;
        }
    }

    // Count CRTCs
    for (uint32_t i = 0; i < DRM_MAX_CRTCS_PER_DEVICE; i++) {
        if (dev->resource_mgr.crtcs[i]) {
            res->count_crtcs++;
        }
    }

    // Count connectors
    for (uint32_t i = 0; i < DRM_MAX_CONNECTORS_PER_DEVICE; i++) {
        if (dev->resource_mgr.connectors[i]) {
            res->count_connectors++;
        }
    }

    // Count encoders
    for (uint32_t i = 0; i < DRM_MAX_ENCODERS_PER_DEVICE; i++) {
        if (dev->resource_mgr.encoders[i]) {
            res->count_encoders++;
        }
    }

    uint32_t width, height, bpp;
    if (dev->op->get_display_info) {
        dev->op->get_display_info(dev, &width, &height, &bpp);
        res->min_width = width;
        res->min_height = height;
        res->max_width = width;
        res->max_height = height;
    } else {
        res->min_width = 0;
        res->min_height = 0;
        res->max_width = 0;
        res->max_height = 0;
    }

    // Fill encoder IDs if pointer provided
    if (res->encoder_id_ptr && res->count_encoders > 0) {
        uint32_t *encoder_ids = (uint32_t *)(uintptr_t)res->encoder_id_ptr;
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_ENCODERS_PER_DEVICE; i++) {
            if (dev->resource_mgr.encoders[i]) {
                encoder_ids[idx++] = dev->resource_mgr.encoders[i]->id;
            }
        }
    }

    // Fill CRTC IDs if pointer provided
    if (res->crtc_id_ptr && res->count_crtcs > 0) {
        uint32_t *crtc_ids = (uint32_t *)(uintptr_t)res->crtc_id_ptr;
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_CRTCS_PER_DEVICE; i++) {
            if (dev->resource_mgr.crtcs[i]) {
                crtc_ids[idx++] = dev->resource_mgr.crtcs[i]->id;
            }
        }
    }

    // Fill connector IDs if pointer provided
    if (res->connector_id_ptr && res->count_connectors > 0) {
        uint32_t *connector_ids = (uint32_t *)(uintptr_t)res->connector_id_ptr;
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_CONNECTORS_PER_DEVICE; i++) {
            if (dev->resource_mgr.connectors[i]) {
                connector_ids[idx++] = dev->resource_mgr.connectors[i]->id;
            }
        }
    }

    // Fill framebuffer IDs if pointer provided
    if (res->fb_id_ptr && res->count_fbs > 0) {
        uint32_t *fb_ids = (uint32_t *)(uintptr_t)res->fb_id_ptr;
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; i++) {
            if (dev->resource_mgr.framebuffers[i]) {
                fb_ids[idx++] = dev->resource_mgr.framebuffers[i]->id;
            }
        }
    }

    return 0;
}

/**
 * drm_ioctl_mode_getcrtc - Handle DRM_IOCTL_MODE_GETCRTC
 */
int drm_ioctl_mode_getcrtc(drm_device_t *dev, void *arg) {
    struct drm_mode_crtc *crtc = (struct drm_mode_crtc *)arg;

    // Find the CRTC by ID
    drm_crtc_t *crtc_obj = drm_crtc_get(&dev->resource_mgr, crtc->crtc_id);
    if (!crtc_obj) {
        return -ENOENT;
    }

    uint32_t width = 0, height = 0, bpp = 0;
    if (dev->op->get_display_info) {
        dev->op->get_display_info(dev, &width, &height, &bpp);
    }

    struct drm_mode_modeinfo mode = {
        .clock = width * HZ,
        .hdisplay = width,
        .hsync_start = width + 16,
        .hsync_end = width + 16 + 96,
        .htotal = width + 16 + 96 + 48,
        .vdisplay = height,
        .vsync_start = height + 10,
        .vsync_end = height + 10 + 2,
        .vtotal = height + 10 + 2 + 33,
        .vrefresh = HZ,
    };

    if (width > 0 && height > 0) {
        sprintf(mode.name, "%dx%d", width, height);
    } else {
        strcpy(mode.name, "unknown");
    }

    crtc->gamma_size = 0;
    crtc->mode_valid = 1;
    memcpy(&crtc->mode, &mode, sizeof(struct drm_mode_modeinfo));
    crtc->fb_id = crtc_obj->fb_id;
    crtc->x = crtc_obj->x;
    crtc->y = crtc_obj->y;

    // Release reference
    drm_crtc_free(&dev->resource_mgr, crtc_obj->id);
    return 0;
}

/**
 * drm_ioctl_mode_getencoder - Handle DRM_IOCTL_MODE_GETENCODER
 */
int drm_ioctl_mode_getencoder(drm_device_t *dev, void *arg) {
    struct drm_mode_get_encoder *enc = (struct drm_mode_get_encoder *)arg;

    // Find the encoder by ID
    drm_encoder_t *encoder =
        drm_encoder_get(&dev->resource_mgr, enc->encoder_id);
    if (!encoder) {
        return -ENOENT;
    }

    enc->encoder_type = encoder->type;
    enc->crtc_id = encoder->crtc_id;
    enc->possible_crtcs = encoder->possible_crtcs;
    enc->possible_clones = encoder->possible_clones;

    // Release reference
    drm_encoder_free(&dev->resource_mgr, encoder->id);
    return 0;
}

/**
 * drm_ioctl_mode_create_dumb - Handle DRM_IOCTL_MODE_CREATE_DUMB
 */
int drm_ioctl_mode_create_dumb(drm_device_t *dev, void *arg) {
    if (!dev->op->create_dumb) {
        return -ENOSYS;
    }
    return dev->op->create_dumb(dev, (struct drm_mode_create_dumb *)arg);
}

/**
 * drm_ioctl_mode_map_dumb - Handle DRM_IOCTL_MODE_MAP_DUMB
 */
int drm_ioctl_mode_map_dumb(drm_device_t *dev, void *arg) {
    if (!dev->op->map_dumb) {
        return -ENOSYS;
    }
    return dev->op->map_dumb(dev, (struct drm_mode_map_dumb *)arg);
}

/**
 * drm_ioctl_mode_getconnector - Handle DRM_IOCTL_MODE_GETCONNECTOR
 */
int drm_ioctl_mode_getconnector(drm_device_t *dev, void *arg) {
    struct drm_mode_get_connector *conn = (struct drm_mode_get_connector *)arg;

    // Find the connector by ID
    drm_connector_t *connector =
        drm_connector_get(&dev->resource_mgr, conn->connector_id);
    if (!connector) {
        return -ENOENT;
    }

    conn->connection = connector->connection;
    conn->count_modes = connector->count_modes;
    conn->count_props = connector->count_props;
    conn->count_encoders = 1; // For now, assume 1 encoder per connector

    // Fill modes if pointer provided
    struct drm_mode_modeinfo *mode =
        (struct drm_mode_modeinfo *)(uintptr_t)conn->modes_ptr;
    if (mode && connector->modes && connector->count_modes > 0) {
        memcpy(mode, connector->modes,
               connector->count_modes * sizeof(struct drm_mode_modeinfo));
    }

    // Fill encoders if pointer provided
    uint32_t *encoders = (uint32_t *)(uintptr_t)conn->encoders_ptr;
    if (encoders && conn->count_encoders > 0) {
        encoders[0] = connector->encoder_id;
    }

    // Fill properties if pointers provided
    if (conn->props_ptr && conn->prop_values_ptr &&
        connector->count_props > 0) {
        uint32_t *prop_ids = (uint32_t *)(uintptr_t)conn->props_ptr;
        uint64_t *prop_values = (uint64_t *)(uintptr_t)conn->prop_values_ptr;
        for (uint32_t i = 0; i < connector->count_props; i++) {
            prop_ids[i] = connector->prop_ids[i];
            prop_values[i] = connector->prop_values[i];
        }
    }

    // Release reference
    drm_connector_free(&dev->resource_mgr, connector->id);
    return 0;
}

/**
 * drm_ioctl_mode_getfb - Handle DRM_IOCTL_MODE_GETFB
 */
int drm_ioctl_mode_getfb(drm_device_t *dev, void *arg) {
    struct drm_mode_fb_cmd *fb_cmd = (struct drm_mode_fb_cmd *)arg;

    // Find the framebuffer by ID
    drm_framebuffer_t *fb =
        drm_framebuffer_get(&dev->resource_mgr, fb_cmd->fb_id);
    if (!fb) {
        return -ENOENT;
    }

    fb_cmd->width = fb->width;
    fb_cmd->height = fb->height;
    fb_cmd->pitch = fb->pitch;
    fb_cmd->bpp = fb->bpp;
    fb_cmd->depth = fb->depth;
    fb_cmd->handle = fb->handle;

    // Release reference
    drm_framebuffer_free(&dev->resource_mgr, fb->id);
    return 0;
}

/**
 * drm_ioctl_mode_addfb - Handle DRM_IOCTL_MODE_ADDFB
 */
int drm_ioctl_mode_addfb(drm_device_t *dev, void *arg) {
    if (!dev->op->add_fb) {
        return -ENOSYS;
    }
    return dev->op->add_fb(dev, (struct drm_mode_fb_cmd *)arg);
}

/**
 * drm_ioctl_mode_addfb2 - Handle DRM_IOCTL_MODE_ADDFB2
 */
int drm_ioctl_mode_addfb2(drm_device_t *dev, void *arg) {
    if (!dev->op->add_fb2) {
        return -ENOSYS;
    }
    return dev->op->add_fb2(dev, (struct drm_mode_fb_cmd2 *)arg);
}

/**
 * drm_ioctl_mode_setcrtc - Handle DRM_IOCTL_MODE_SETCRTC
 */
int drm_ioctl_mode_setcrtc(drm_device_t *dev, void *arg) {
    struct drm_mode_crtc *crtc_cmd = (struct drm_mode_crtc *)arg;

    // Find the CRTC by ID
    drm_crtc_t *crtc = drm_crtc_get(&dev->resource_mgr, crtc_cmd->crtc_id);
    if (!crtc) {
        return -ENOENT;
    }

    // Update CRTC state
    crtc->fb_id = crtc_cmd->fb_id;
    crtc->x = crtc_cmd->x;
    crtc->y = crtc_cmd->y;
    if (crtc_cmd->mode_valid) {
        memcpy(&crtc->mode, &crtc_cmd->mode, sizeof(struct drm_mode_modeinfo));
    }

    // Call driver to set CRTC if supported
    int ret = 0;
    if (dev->op->set_crtc) {
        ret = dev->op->set_crtc(dev, crtc_cmd);
    }

    // Release reference
    drm_crtc_free(&dev->resource_mgr, crtc->id);
    return ret;
}

/**
 * drm_ioctl_mode_getplaneresources - Handle DRM_IOCTL_MODE_GETPLANERESOURCES
 */
int drm_ioctl_mode_getplaneresources(drm_device_t *dev, void *arg) {
    struct drm_mode_get_plane_res *res = (struct drm_mode_get_plane_res *)arg;

    // Count available planes
    res->count_planes = 0;
    for (uint32_t i = 0; i < DRM_MAX_PLANES_PER_DEVICE; i++) {
        if (dev->resource_mgr.planes[i]) {
            res->count_planes++;
        }
    }

    // Fill plane IDs if pointer provided
    if (res->plane_id_ptr && res->count_planes > 0) {
        uint32_t *plane_ids = (uint32_t *)(uintptr_t)res->plane_id_ptr;
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_PLANES_PER_DEVICE; i++) {
            if (dev->resource_mgr.planes[i]) {
                plane_ids[idx++] = dev->resource_mgr.planes[i]->id;
            }
        }
    }

    return 0;
}

/**
 * drm_ioctl_mode_getplane - Handle DRM_IOCTL_MODE_GETPLANE
 */
int drm_ioctl_mode_getplane(drm_device_t *dev, void *arg) {
    struct drm_mode_get_plane *plane_cmd = (struct drm_mode_get_plane *)arg;

    // Find the plane by ID
    drm_plane_t *plane = drm_plane_get(&dev->resource_mgr, plane_cmd->plane_id);
    if (!plane) {
        return -ENOENT;
    }

    plane_cmd->plane_id = plane->id;
    plane_cmd->crtc_id = plane->crtc_id;
    plane_cmd->fb_id = plane->fb_id;
    plane_cmd->possible_crtcs = plane->possible_crtcs;
    plane_cmd->gamma_size = plane->gamma_size;
    plane_cmd->count_format_types = plane->count_format_types;

    // Fill format types if pointer provided
    if (plane_cmd->format_type_ptr && plane->count_format_types > 0 &&
        plane->format_types) {
        uint32_t *formats = (uint32_t *)(uintptr_t)plane_cmd->format_type_ptr;
        for (uint32_t i = 0; i < plane->count_format_types; i++) {
            formats[i] = plane->format_types[i];
        }
    }

    // Release reference
    drm_plane_free(&dev->resource_mgr, plane->id);
    return 0;
}

/**
 * drm_ioctl_mode_setplane - Handle DRM_IOCTL_MODE_SETPLANE
 */
int drm_ioctl_mode_setplane(drm_device_t *dev, void *arg) {
    struct drm_mode_set_plane *plane_cmd = (struct drm_mode_set_plane *)arg;

    // Find the plane by ID
    drm_plane_t *plane = drm_plane_get(&dev->resource_mgr, plane_cmd->plane_id);
    if (!plane) {
        return -ENOENT;
    }

    // Update plane state
    plane->crtc_id = plane_cmd->crtc_id;
    plane->fb_id = plane_cmd->fb_id;

    // Call driver to set plane (if supported)
    int ret = 0;
    if (dev->op->set_plane) {
        ret = dev->op->set_plane(dev, plane_cmd);
    }

    // Release reference
    drm_plane_free(&dev->resource_mgr, plane->id);
    return ret;
}

/**
 * drm_ioctl_mode_getproperty - Handle DRM_IOCTL_MODE_GETPROPERTY
 */
int drm_ioctl_mode_getproperty(drm_device_t *dev, void *arg) {
    struct drm_mode_get_property *prop = (struct drm_mode_get_property *)arg;

    switch (prop->prop_id) {
    case DRM_PROPERTY_ID_PLANE_TYPE:
        prop->flags = DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE;
        strncpy((char *)prop->name, "type", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0'; // 确保 null 终止

        prop->count_enum_blobs = 3; // Primary, Overlay, Cursor
        if (prop->enum_blob_ptr) {
            struct drm_mode_property_enum *enums =
                (struct drm_mode_property_enum *)prop->enum_blob_ptr;

            strncpy(enums[0].name, "Primary", DRM_PROP_NAME_LEN);
            enums[0].value = DRM_PLANE_TYPE_PRIMARY;

            strncpy(enums[1].name, "Overlay", DRM_PROP_NAME_LEN);
            enums[1].value = DRM_PLANE_TYPE_OVERLAY;

            strncpy(enums[2].name, "Cursor", DRM_PROP_NAME_LEN);
            enums[2].value = DRM_PLANE_TYPE_CURSOR;
        }

        // ENUM 属性不需要设置 values (除非有默认值范围)
        prop->count_values = 0;
        return 0;

    case DRM_CRTC_MODE_ID_PROP_ID:
        prop->flags = DRM_MODE_PROP_BLOB | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "MODE_ID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        // BLOB 属性不设置 count_enum_blobs
        prop->count_enum_blobs = 0;

        // 对于 BLOB 属性，count_values 通常为 0
        prop->count_values = 0;
        return 0;

    case DRM_CRTC_ACTIVE_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "ACTIVE", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;

        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t *values = (uint64_t *)(uintptr_t)prop->values_ptr;
            values[0] = 0; // min
            values[1] = 1; // max
        }
        return 0;

    case DRM_FB_WIDTH_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "WIDTH", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t *values = (uint64_t *)(uintptr_t)prop->values_ptr;
            values[0] = 1;    // min
            values[1] = 8192; // max
        }
        return 0;
    case DRM_FB_HEIGHT_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "HEIGHT", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t *values = (uint64_t *)(uintptr_t)prop->values_ptr;
            values[0] = 1;    // min
            values[1] = 8192; // max
        }
        return 0;
    case DRM_FB_BPP_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "BPP", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t *values = (uint64_t *)(uintptr_t)prop->values_ptr;
            values[0] = 8;  // min
            values[1] = 32; // max
        }
        return 0;
    case DRM_FB_DEPTH_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "DEPTH", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t *values = (uint64_t *)(uintptr_t)prop->values_ptr;
            values[0] = 8;  // min
            values[1] = 32; // max
        }
        return 0;

    case DRM_CONNECTOR_DPMS_PROP_ID:
        prop->flags = DRM_MODE_PROP_ENUM;
        strncpy((char *)prop->name, "DPMS", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 4;
        if (prop->enum_blob_ptr) {
            struct drm_mode_property_enum *enums =
                (struct drm_mode_property_enum *)prop->enum_blob_ptr;

            strncpy(enums[0].name, "On", DRM_PROP_NAME_LEN);
            enums[0].value = DRM_MODE_DPMS_ON;

            strncpy(enums[1].name, "Standby", DRM_PROP_NAME_LEN);
            enums[1].value = DRM_MODE_DPMS_STANDBY;

            strncpy(enums[2].name, "Suspend", DRM_PROP_NAME_LEN);
            enums[2].value = DRM_MODE_DPMS_SUSPEND;

            strncpy(enums[3].name, "Off", DRM_PROP_NAME_LEN);
            enums[3].value = DRM_MODE_DPMS_OFF;
        }

        prop->count_values = 0;
        return 0;

    case DRM_CONNECTOR_EDID_PROP_ID:
        prop->flags = DRM_MODE_PROP_BLOB;
        strncpy((char *)prop->name, "EDID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 0;
        return 0;

    case DRM_CONNECTOR_CRTC_ID_PROP_ID:
        prop->flags = DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "CRTC_ID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';

        prop->count_enum_blobs = 0;
        prop->count_values = 0;
        return 0;

    default:
        printk("drm: Unsupported property ID: %u\n", prop->prop_id);
        return -EINVAL;
    }
}

/**
 * drm_ioctl_mode_getpropblob - Handle DRM_IOCTL_MODE_GETPROPBLOB
 */
int drm_ioctl_mode_getpropblob(drm_device_t *dev, void *arg) {
    struct drm_mode_get_blob *blob = (struct drm_mode_get_blob *)arg;
    switch (blob->blob_id) {
    case DRM_BLOB_ID_PLANE_TYPE:
        memcpy((void *)blob->data, "Primary", 7);
        break;

    default:
        printk("drm: Invalid blob id %d\n", blob->blob_id);
        return -ENOENT;
    }

    return 0;
}

/**
 * drm_ioctl_mode_obj_getproperties - Handle DRM_IOCTL_MODE_OBJ_GETPROPERTIES
 */
int drm_ioctl_mode_obj_getproperties(drm_device_t *dev, void *arg) {
    struct drm_mode_obj_get_properties *props =
        (struct drm_mode_obj_get_properties *)arg;

    switch (props->obj_type) {
    case DRM_MODE_OBJECT_PLANE: {
        // 查找对应的 plane
        drm_plane_t *plane = NULL;
        for (int idx = 0; idx < DRM_MAX_PLANES_PER_DEVICE; idx++) {
            if (dev->resource_mgr.planes[idx] &&
                dev->resource_mgr.planes[idx]->id == props->obj_id) {
                plane = dev->resource_mgr.planes[idx];
                break;
            }
        }

        if (!plane) {
            return -ENOENT;
        }

        // Plane 通常有多个属性
        props->count_props =
            7; // type, FB_ID, CRTC_ID, CRTC_X, CRTC_Y, CRTC_W, CRTC_H 等

        if (props->props_ptr) {
            uint32_t *prop_ids = (uint32_t *)(uintptr_t)props->props_ptr;

            prop_ids[0] = DRM_PROPERTY_ID_PLANE_TYPE;
            prop_ids[1] = DRM_PROPERTY_ID_FB_ID;
            prop_ids[2] = DRM_PROPERTY_ID_CRTC_ID;
            drm_crtc_t *crtc = drm_crtc_get(&dev->resource_mgr, plane->crtc_id);
            prop_ids[3] = DRM_PROPERTY_ID_CRTC_X;
            prop_ids[4] = DRM_PROPERTY_ID_CRTC_Y;
            prop_ids[5] = DRM_PROPERTY_ID_CRTC_W;
            prop_ids[6] = DRM_PROPERTY_ID_CRTC_H;
            drm_crtc_free(&dev->resource_mgr, crtc->id);
        }
        if (props->prop_values_ptr) {
            uint64_t *prop_values =
                (uint64_t *)(uintptr_t)props->prop_values_ptr;

            prop_values[0] = plane->plane_type;
            prop_values[1] = plane->fb_id;   // 当前关联的 framebuffer
            prop_values[2] = plane->crtc_id; // 当前关联的 CRTC
            drm_crtc_t *crtc = drm_crtc_get(&dev->resource_mgr, plane->crtc_id);
            prop_values[3] = crtc->x;
            prop_values[4] = crtc->y;
            prop_values[5] = crtc->w;
            prop_values[6] = crtc->h;
            drm_crtc_free(&dev->resource_mgr, crtc->id);
        }

        break;
    }

    case DRM_MODE_OBJECT_CRTC: {
        drm_crtc_t *crtc = NULL;
        for (int idx = 0; idx < DRM_MAX_CRTCS_PER_DEVICE; idx++) {
            if (dev->resource_mgr.crtcs[idx] &&
                dev->resource_mgr.crtcs[idx]->id == props->obj_id) {
                crtc = dev->resource_mgr.crtcs[idx];
                break;
            }
        }

        if (!crtc) {
            return -ENOENT;
        }

        props->count_props = 2;

        if (props->props_ptr) {
            uint32_t *prop_ids = (uint32_t *)(uintptr_t)props->props_ptr;

            prop_ids[0] = DRM_CRTC_ACTIVE_PROP_ID;
            prop_ids[1] = DRM_CRTC_MODE_ID_PROP_ID;
        }
        if (props->prop_values_ptr) {
            uint64_t *prop_values =
                (uint64_t *)(uintptr_t)props->prop_values_ptr;

            prop_values[0] = 1; // CRTC 的实际状态
            prop_values[1] = 1; // 指向 mode blob 的 ID
        }
        break;
    }

    case DRM_MODE_OBJECT_FB: {
        drm_framebuffer_t *fb = NULL;
        for (int idx = 0; idx < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; idx++) {
            if (dev->resource_mgr.framebuffers[idx] &&
                dev->resource_mgr.framebuffers[idx]->id == props->obj_id) {
                fb = dev->resource_mgr.framebuffers[idx];
                break;
            }
        }

        if (!fb) {
            return -ENOENT;
        }

        props->count_props = 4;

        if (props->props_ptr) {
            uint32_t *prop_ids = (uint32_t *)(uintptr_t)props->props_ptr;

            prop_ids[0] = DRM_FB_WIDTH_PROP_ID;
            prop_ids[1] = DRM_FB_HEIGHT_PROP_ID;
            prop_ids[2] = DRM_FB_BPP_PROP_ID;
            prop_ids[3] = DRM_FB_DEPTH_PROP_ID;
        }
        if (props->prop_values_ptr) {
            uint64_t *prop_values =
                (uint64_t *)(uintptr_t)props->prop_values_ptr;

            prop_values[0] = fb->width;
            prop_values[1] = fb->height;
            prop_values[2] = fb->bpp;
            prop_values[3] = fb->depth;
        }

        break;
    }

    case DRM_MODE_OBJECT_CONNECTOR: {
        drm_connector_t *connector = NULL;
        for (int idx = 0; idx < DRM_MAX_CONNECTORS_PER_DEVICE; idx++) {
            if (dev->resource_mgr.connectors[idx] &&
                dev->resource_mgr.connectors[idx]->id == props->obj_id) {
                connector = dev->resource_mgr.connectors[idx];
                break;
            }
        }

        if (!connector) {
            return -ENOENT;
        }

        props->count_props = 3;

        if (props->props_ptr) {
            uint32_t *prop_ids = (uint32_t *)(uintptr_t)props->props_ptr;
            prop_ids[0] = DRM_CONNECTOR_DPMS_PROP_ID;
            prop_ids[1] = DRM_CONNECTOR_EDID_PROP_ID;
            prop_ids[2] = DRM_CONNECTOR_CRTC_ID_PROP_ID;
        }
        if (props->prop_values_ptr) {
            uint64_t *prop_values =
                (uint64_t *)(uintptr_t)props->prop_values_ptr;
            prop_values[0] = DRM_MODE_DPMS_ON;
            prop_values[1] = 0;
            prop_values[2] = connector->crtc_id;
        }
        break;
    }

    default:
        printk("drm: Unsupported object type: %u\n", props->obj_type);
        return -EINVAL;
    }

    return 0;
}

/**
 * drm_ioctl_set_client_cap - Handle DRM_IOCTL_SET_CLIENT_CAP
 */
int drm_ioctl_set_client_cap(drm_device_t *dev, void *arg) {
    struct drm_set_client_cap *cap = (struct drm_set_client_cap *)arg;
    switch (cap->capability) {
    case DRM_CLIENT_CAP_ATOMIC:
        return 0;
    case DRM_CLIENT_CAP_UNIVERSAL_PLANES:
        return 0;
    case DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT:
        return 0;
    default:
        printk("drm: Invalid client capability %d\n", cap->capability);
        return -EINVAL;
    }
}

/**
 * drm_ioctl_wait_vblank - Handle DRM_IOCTL_WAIT_VBLANK
 */
int drm_ioctl_wait_vblank(drm_device_t *dev, void *arg) {
    union drm_wait_vblank *vbl = (union drm_wait_vblank *)arg;

    uint64_t seq = dev->vblank_counter;

    if (vbl->request.type & _DRM_VBLANK_RELATIVE)
        vbl->request.sequence += seq;
    else
        vbl->request.sequence = seq;

    vbl->reply.sequence = vbl->request.sequence;
    vbl->reply.tval_sec = nano_time() / 1000000000ULL;
    vbl->reply.tval_usec = (nano_time() % 1000000000ULL) / 1000ULL;

    return 0;
}

/**
 * drm_ioctl_get_unique - Handle DRM_IOCTL_GET_UNIQUE
 */
int drm_ioctl_get_unique(drm_device_t *dev, void *arg) {
    struct drm_unique *u = (struct drm_unique *)arg;
    (void)dev;

    if (u->unique)
        strcpy(u->unique, "pci:0000:00:00.0");
    u->unique_len = 17;

    return 0;
}

/**
 * drm_ioctl_page_flip - Handle DRM_IOCTL_MODE_PAGE_FLIP
 */
int drm_ioctl_page_flip(drm_device_t *dev, void *arg) {
    if (!dev->op->page_flip) {
        return -ENOSYS;
    }
    return dev->op->page_flip(dev, (struct drm_mode_crtc_page_flip *)arg);
}

/**
 * drm_ioctl_cursor - Handle DRM_IOCTL_MODE_CURSOR
 */
int drm_ioctl_cursor(drm_device_t *dev, void *arg) {
    struct drm_mode_cursor *cmd = (struct drm_mode_cursor *)arg;
    if (cmd->flags & DRM_MODE_CURSOR_BO) {
        return 0;
    } else if (cmd->flags & DRM_MODE_CURSOR_MOVE) {
        return 0;
    }

    return 0;
}

/**
 * drm_ioctl_cursor2 - Handle DRM_IOCTL_MODE_CURSOR2
 */
int drm_ioctl_cursor2(drm_device_t *dev, void *arg) {
    struct drm_mode_cursor2 *cmd = (struct drm_mode_cursor2 *)arg;
    if (cmd->flags & DRM_MODE_CURSOR_BO) {
        return 0;
    } else if (cmd->flags & DRM_MODE_CURSOR_MOVE) {
        return 0;
    }

    return 0;
}

/**
 * drm_ioctl_atomic - Handle DRM_IOCTL_MODE_ATOMIC
 */
int drm_ioctl_atomic(drm_device_t *dev, void *arg) {
    // struct drm_mode_atomic *cmd = (struct drm_mode_atomic *)arg;
    // if (cmd->flags & DRM_MODE_ATOMIC_TEST_ONLY) {
    //     return 0;
    // } else if (cmd->flags & DRM_MODE_CURSOR_MOVE) {
    //     return 0;
    // }

    return 0;
}

/**
 * drm_ioctl_get_magic - Handle DRM_IOCTL_GET_MAGIC
 */
int drm_ioctl_get_magic(drm_device_t *dev, void *arg) {
    drm_auth_t *auth = (drm_auth_t *)arg;
    (void)dev;

    auth->magic = 0x12345678;
    return 0;
}

/**
 * drm_ioctl_auth_magic - Handle DRM_IOCTL_AUTH_MAGIC
 */
int drm_ioctl_auth_magic(drm_device_t *dev, void *arg) {
    drm_auth_t *auth = (drm_auth_t *)arg;
    if (auth->magic != 0x12345678)
        return -EINVAL;

    return 0;
}

/**
 * drm_ioctl_set_master - Handle DRM_IOCTL_SET_MASTER
 */
int drm_ioctl_set_master(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_drop_master - Handle DRM_IOCTL_DROP_MASTER
 */
int drm_ioctl_drop_master(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_gamma - Handle DRM_IOCTL_MODE_GETGAMMA/DRM_IOCTL_MODE_SETGAMMA
 */
int drm_ioctl_gamma(drm_device_t *dev, void *arg, ssize_t cmd) {
    (void)dev;
    (void)arg;
    (void)cmd;
    return 0;
}

/**
 * drm_ioctl_dirtyfb - Handle DRM_IOCTL_MODE_DIRTYFB
 */
int drm_ioctl_dirtyfb(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_mode_list_lessees - Handle DRM_IOCTL_MODE_LIST_LESSEES
 */
int drm_ioctl_mode_list_lessees(drm_device_t *dev, void *arg) {
    struct drm_mode_list_lessees *l = (struct drm_mode_list_lessees *)arg;
    (void)dev;

    l->count_lessees = 0;
    return 0;
}

/**
 * drm_ioctl - Main DRM ioctl handler
 */
ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg) {
    drm_device_t *dev = (drm_device_t *)data;
    int ret = -EINVAL;

    switch (cmd & 0xffffffff) {
    case DRM_IOCTL_VERSION:
        ret = drm_ioctl_version(dev, (void *)arg);
        break;
    case DRM_IOCTL_GET_CAP:
        ret = drm_ioctl_get_cap(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETRESOURCES:
        ret = drm_ioctl_mode_getresources(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETCRTC:
        ret = drm_ioctl_mode_getcrtc(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETENCODER:
        ret = drm_ioctl_mode_getencoder(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_CREATE_DUMB:
        ret = drm_ioctl_mode_create_dumb(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_MAP_DUMB:
        ret = drm_ioctl_mode_map_dumb(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_DESTROY_DUMB:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_MODE_GETCONNECTOR:
        ret = drm_ioctl_mode_getconnector(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETFB:
        ret = drm_ioctl_mode_getfb(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_ADDFB:
        ret = drm_ioctl_mode_addfb(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_ADDFB2:
        ret = drm_ioctl_mode_addfb2(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_RMFB:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_MODE_SETCRTC:
        ret = drm_ioctl_mode_setcrtc(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETPLANERESOURCES:
        ret = drm_ioctl_mode_getplaneresources(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETPLANE:
        ret = drm_ioctl_mode_getplane(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_SETPLANE:
        ret = drm_ioctl_mode_setplane(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETPROPERTY:
        ret = drm_ioctl_mode_getproperty(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETPROPBLOB:
        ret = drm_ioctl_mode_getpropblob(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_SETPROPERTY:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_MODE_OBJ_GETPROPERTIES:
        ret = drm_ioctl_mode_obj_getproperties(dev, (void *)arg);
        break;
    case DRM_IOCTL_SET_CLIENT_CAP:
        ret = drm_ioctl_set_client_cap(dev, (void *)arg);
        break;
    case DRM_IOCTL_SET_MASTER:
        ret = drm_ioctl_set_master(dev, (void *)arg);
        break;
    case DRM_IOCTL_DROP_MASTER:
        ret = drm_ioctl_drop_master(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_GETGAMMA:
        ret = drm_ioctl_gamma(dev, (void *)arg, cmd);
        break;
    case DRM_IOCTL_MODE_SETGAMMA:
        ret = drm_ioctl_gamma(dev, (void *)arg, cmd);
        break;
    case DRM_IOCTL_MODE_DIRTYFB:
        ret = drm_ioctl_dirtyfb(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_PAGE_FLIP:
        ret = drm_ioctl_page_flip(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_CURSOR:
        ret = drm_ioctl_cursor(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_CURSOR2:
        ret = drm_ioctl_cursor2(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_ATOMIC:
        ret = drm_ioctl_atomic(dev, (void *)arg);
        break;
    case DRM_IOCTL_WAIT_VBLANK:
        ret = drm_ioctl_wait_vblank(dev, (void *)arg);
        break;
    case DRM_IOCTL_GET_UNIQUE:
        ret = drm_ioctl_get_unique(dev, (void *)arg);
        break;
    case DRM_IOCTL_MODE_LIST_LESSEES:
        ret = drm_ioctl_mode_list_lessees(dev, (void *)arg);
        break;
    case DRM_IOCTL_SET_VERSION:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_GET_MAGIC:
        ret = drm_ioctl_get_magic(dev, (void *)arg);
        break;
    case DRM_IOCTL_AUTH_MAGIC:
        ret = drm_ioctl_auth_magic(dev, (void *)arg);
        break;
    default:
        printk("drm: Unsupported ioctl: cmd = %#010lx\n", cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}