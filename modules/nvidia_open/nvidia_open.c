#include "nvidia_open.h"
#include <libs/aether/pci.h>
#include <libs/aether/irq.h>
#include <libs/aether/mm.h>
#include <libs/klibc.h>
#include <nvUnixVersion.h>

nvidia_device_t *nvidia_gpus[MAX_NVIDIA_GPU_NUM];
uint64_t nvidia_gpu_count = 0;
static void *nvidia_scanout_maps[MAX_NVIDIA_GPU_NUM][32];
volatile NvS32 nvidia_open_irq_nesting = 0;
volatile NvU64 nvidia_open_irq_total = 0;

extern spinlock_t nvKmsLock;

const struct NvKmsKapiFunctionsTable *nvKms;

static void nvidia_unregister_gpu(nvidia_device_t *nv_dev) {
    if (!nv_dev) {
        return;
    }

    for (uint64_t i = 0; i < nvidia_gpu_count; i++) {
        if (nvidia_gpus[i] != nv_dev) {
            continue;
        }

        for (uint64_t j = i + 1; j < nvidia_gpu_count; j++) {
            nvidia_gpus[j - 1] = nvidia_gpus[j];
            memcpy(nvidia_scanout_maps[j - 1], nvidia_scanout_maps[j],
                   sizeof(nvidia_scanout_maps[j - 1]));
        }
        nvidia_gpus[nvidia_gpu_count - 1] = NULL;
        memset(nvidia_scanout_maps[nvidia_gpu_count - 1], 0,
               sizeof(nvidia_scanout_maps[nvidia_gpu_count - 1]));
        nvidia_gpu_count--;
        return;
    }
}

int nvidia_set_crtc(drm_device_t *drm_dev, struct drm_mode_crtc *crtc);
int nvidia_page_flip(struct drm_device *dev,
                     struct drm_mode_crtc_page_flip *flip);

static bool nvidia_handle_to_index(uint32_t handle, uint32_t *idx) {
    if (!idx || handle == 0 || handle > 32) {
        return false;
    }

    *idx = handle - 1;
    return true;
}

static nvidia_fb_t *nvidia_fb_by_handle(nvidia_device_t *nv_dev,
                                        uint32_t handle) {
    uint32_t idx = 0;
    if (!nv_dev || !nvidia_handle_to_index(handle, &idx)) {
        return NULL;
    }

    if (!nv_dev->framebuffers[idx].in_use) {
        return NULL;
    }

    return &nv_dev->framebuffers[idx];
}

static nvidia_fb_t *nvidia_fb_by_fb_id(nvidia_device_t *nv_dev,
                                       uint32_t fb_id) {
    if (!nv_dev || !fb_id) {
        return NULL;
    }

    for (uint32_t i = 0; i < 32; i++) {
        if (nv_dev->framebuffers[i].in_use &&
            nv_dev->framebuffers[i].fb_id == fb_id) {
            return &nv_dev->framebuffers[i];
        }
    }

    return NULL;
}

static bool
nvidia_drm_to_surface_format(uint32_t fourcc,
                             enum NvKmsSurfaceMemoryFormat *format) {
    if (!format) {
        return false;
    }

    switch (fourcc) {
    case DRM_FORMAT_ARGB8888:
        *format = NvKmsSurfaceMemoryFormatA8R8G8B8;
        return true;
    case DRM_FORMAT_XRGB8888:
        *format = NvKmsSurfaceMemoryFormatX8R8G8B8;
        return true;
    case DRM_FORMAT_XBGR8888:
        *format = NvKmsSurfaceMemoryFormatX8B8G8R8;
        return true;
    case DRM_FORMAT_ABGR8888:
        *format = NvKmsSurfaceMemoryFormatA8B8G8R8;
        return true;
    default:
        return false;
    }
}

static int nvidia_legacy_fb_to_drm_format(uint32_t bpp, uint32_t depth,
                                          uint32_t *fourcc, uint32_t *out_bpp,
                                          uint32_t *out_depth) {
    if (!fourcc) {
        return -EINVAL;
    }

    uint32_t effective_bpp = bpp ? bpp : 32;
    uint32_t effective_depth =
        depth ? depth : (effective_bpp == 32 ? 24 : effective_bpp);

    switch (effective_bpp) {
    case 32:
        if (effective_depth == 24) {
            *fourcc = DRM_FORMAT_XRGB8888;
        } else if (effective_depth == 32) {
            *fourcc = DRM_FORMAT_ARGB8888;
        } else {
            return -EINVAL;
        }
        break;
    default:
        return -EINVAL;
    }

    if (out_bpp) {
        *out_bpp = effective_bpp;
    }
    if (out_depth) {
        *out_depth = effective_depth;
    }

    return 0;
}

static int nvidia_fb_format_to_depth(uint32_t fourcc, uint32_t *bpp,
                                     uint32_t *depth) {
    if (!bpp || !depth) {
        return -EINVAL;
    }

    switch (fourcc) {
    case DRM_FORMAT_XRGB8888:
    case DRM_FORMAT_XBGR8888:
        *bpp = 32;
        *depth = 24;
        return 0;
    case DRM_FORMAT_ARGB8888:
    case DRM_FORMAT_ABGR8888:
        *bpp = 32;
        *depth = 32;
        return 0;
    default:
        return -EINVAL;
    }
}

static uint32_t nvidia_signal_format_to_drm(NvKmsConnectorSignalFormat format) {
    switch (format) {
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_TMDS:
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_DP:
        return DRM_MODE_ENCODER_TMDS;
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_LVDS:
        return DRM_MODE_ENCODER_LVDS;
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_VGA:
        return DRM_MODE_ENCODER_DAC;
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_DSI:
        return DRM_MODE_ENCODER_DSI;
    case NVKMS_CONNECTOR_SIGNAL_FORMAT_UNKNOWN:
    default:
        return DRM_MODE_ENCODER_NONE;
    }
}

static uint32_t nvidia_connector_type_to_drm(NvKmsConnectorType type,
                                             bool internal) {
    switch (type) {
    case NVKMS_CONNECTOR_TYPE_DP:
        return internal ? DRM_MODE_CONNECTOR_eDP
                        : DRM_MODE_CONNECTOR_DisplayPort;
    case NVKMS_CONNECTOR_TYPE_VGA:
        return DRM_MODE_CONNECTOR_VGA;
    case NVKMS_CONNECTOR_TYPE_DVI_I:
        return DRM_MODE_CONNECTOR_DVII;
    case NVKMS_CONNECTOR_TYPE_DVI_D:
        return DRM_MODE_CONNECTOR_DVID;
    case NVKMS_CONNECTOR_TYPE_LVDS:
        return DRM_MODE_CONNECTOR_LVDS;
    case NVKMS_CONNECTOR_TYPE_HDMI:
        return DRM_MODE_CONNECTOR_HDMIA;
    case NVKMS_CONNECTOR_TYPE_DSI:
        return DRM_MODE_CONNECTOR_DSI;
    default:
        return DRM_MODE_CONNECTOR_VIRTUAL;
    }
}

static void nvidia_to_drm_mode(const struct NvKmsKapiDisplayMode *mode,
                               struct drm_mode_modeinfo *drm_mode) {
    if (!mode || !drm_mode) {
        return;
    }

    memset(drm_mode, 0, sizeof(*drm_mode));
    drm_mode->clock = (mode->timings.pixelClockHz + 500) / 1000;
    drm_mode->hdisplay = mode->timings.hVisible;
    drm_mode->hsync_start = mode->timings.hSyncStart;
    drm_mode->hsync_end = mode->timings.hSyncEnd;
    drm_mode->htotal = mode->timings.hTotal;
    drm_mode->hskew = mode->timings.hSkew;
    drm_mode->vdisplay = mode->timings.vVisible;
    drm_mode->vsync_start = mode->timings.vSyncStart;
    drm_mode->vsync_end = mode->timings.vSyncEnd;
    drm_mode->vtotal = mode->timings.vTotal;
    drm_mode->vrefresh = (mode->timings.refreshRate + 500) / 1000;

    if (mode->timings.flags.hSyncPos) {
        drm_mode->flags |= DRM_MODE_FLAG_PHSYNC;
    }
    if (mode->timings.flags.hSyncNeg) {
        drm_mode->flags |= DRM_MODE_FLAG_NHSYNC;
    }
    if (mode->timings.flags.vSyncPos) {
        drm_mode->flags |= DRM_MODE_FLAG_PVSYNC;
    }
    if (mode->timings.flags.vSyncNeg) {
        drm_mode->flags |= DRM_MODE_FLAG_NVSYNC;
    }
    if (mode->timings.flags.interlaced) {
        drm_mode->flags |= DRM_MODE_FLAG_INTERLACE;
    }
    if (mode->timings.flags.doubleScan) {
        drm_mode->flags |= DRM_MODE_FLAG_DBLSCAN;
    }

    if (strlen(mode->name)) {
        memcpy(drm_mode->name, mode->name,
               MIN(sizeof(drm_mode->name), sizeof(mode->name)));
        drm_mode->name[sizeof(drm_mode->name) - 1] = '\0';
    } else {
        snprintf(drm_mode->name, sizeof(drm_mode->name), "%dx%d%s",
                 drm_mode->hdisplay, drm_mode->vdisplay,
                 mode->timings.flags.interlaced ? "i" : "");
    }
}

static void nvidia_to_kapi_mode(const struct drm_mode_modeinfo *drm_mode,
                                struct NvKmsKapiDisplayMode *mode) {
    if (!drm_mode || !mode) {
        return;
    }

    memset(mode, 0, sizeof(*mode));
    mode->timings.refreshRate =
        (drm_mode->vrefresh ? drm_mode->vrefresh : HZ) * 1000;
    mode->timings.pixelClockHz = drm_mode->clock * 1000;
    mode->timings.hVisible = drm_mode->hdisplay;
    mode->timings.hSyncStart = drm_mode->hsync_start;
    mode->timings.hSyncEnd = drm_mode->hsync_end;
    mode->timings.hTotal = drm_mode->htotal;
    mode->timings.hSkew = drm_mode->hskew;
    mode->timings.vVisible = drm_mode->vdisplay;
    mode->timings.vSyncStart = drm_mode->vsync_start;
    mode->timings.vSyncEnd = drm_mode->vsync_end;
    mode->timings.vTotal = drm_mode->vtotal;

    mode->timings.flags.hSyncPos = !!(drm_mode->flags & DRM_MODE_FLAG_PHSYNC);
    mode->timings.flags.hSyncNeg = !!(drm_mode->flags & DRM_MODE_FLAG_NHSYNC);
    mode->timings.flags.vSyncPos = !!(drm_mode->flags & DRM_MODE_FLAG_PVSYNC);
    mode->timings.flags.vSyncNeg = !!(drm_mode->flags & DRM_MODE_FLAG_NVSYNC);
    mode->timings.flags.interlaced =
        !!(drm_mode->flags & DRM_MODE_FLAG_INTERLACE);
    mode->timings.flags.doubleScan =
        !!(drm_mode->flags & DRM_MODE_FLAG_DBLSCAN);

    memcpy(mode->name, drm_mode->name,
           MIN(sizeof(mode->name), sizeof(drm_mode->name)));
}

static uint32_t nvidia_get_drm_formats_from_mask(uint64_t mask, uint32_t *out,
                                                 uint32_t max_out) {
    if (!out || !max_out) {
        return 0;
    }

    uint32_t count = 0;
    if ((mask & (1ULL << NvKmsSurfaceMemoryFormatX8R8G8B8)) &&
        count < max_out) {
        out[count++] = DRM_FORMAT_XRGB8888;
    }
    if ((mask & (1ULL << NvKmsSurfaceMemoryFormatA8R8G8B8)) &&
        count < max_out) {
        out[count++] = DRM_FORMAT_ARGB8888;
    }
    if ((mask & (1ULL << NvKmsSurfaceMemoryFormatX8B8G8R8)) &&
        count < max_out) {
        out[count++] = DRM_FORMAT_XBGR8888;
    }
    if ((mask & (1ULL << NvKmsSurfaceMemoryFormatA8B8G8R8)) &&
        count < max_out) {
        out[count++] = DRM_FORMAT_ABGR8888;
    }

    return count;
}

static bool nvidia_get_display_mode(nvidia_device_t *nv_dev,
                                    NvKmsKapiDisplay display,
                                    struct NvKmsKapiDisplayMode *mode,
                                    uint32_t *mm_width, uint32_t *mm_height) {
    if (!nv_dev || !mode) {
        return false;
    }

    bool has_mode = false;
    uint32_t mode_index = 0;
    while (true) {
        struct NvKmsKapiDisplayMode cur_mode;
        NvBool valid = NV_FALSE;
        NvBool preferred = NV_FALSE;
        int ret = nvKms->getDisplayMode(nv_dev->kmsdev, display, mode_index++,
                                        &cur_mode, &valid, &preferred);
        if (ret < 0) {
            return false;
        }
        if (ret == 0) {
            break;
        }
        if (!valid) {
            continue;
        }

        if (!has_mode || preferred) {
            *mode = cur_mode;
            has_mode = true;
            if (mm_width) {
                *mm_width = cur_mode.timings.widthMM;
            }
            if (mm_height) {
                *mm_height = cur_mode.timings.heightMM;
            }
            if (preferred) {
                return true;
            }
        }
    }

    return has_mode;
}

static const struct drm_mode_modeinfo *
nvidia_preferred_connector_mode(const drm_connector_t *connector) {
    if (!connector || !connector->modes || !connector->count_modes) {
        return NULL;
    }

    for (uint32_t i = 0; i < connector->count_modes; i++) {
        if (connector->modes[i].type & DRM_MODE_TYPE_PREFERRED) {
            return &connector->modes[i];
        }
    }

    return &connector->modes[0];
}

static void nvidia_build_incompatible_display_map(nvidia_device_t *nv_dev) {
    if (!nv_dev || !nvKms) {
        return;
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        nv_dev->incompatible_display_mask[i] = 0;
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (!nv_dev->display_connectors[i]) {
            continue;
        }

        struct NvKmsKapiConnectorInfo info;
        memset(&info, 0, sizeof(info));
        if (!nvKms->getConnectorInfo(nv_dev->kmsdev,
                                     nv_dev->display_connectors[i], &info)) {
            continue;
        }

        uint32_t mask = 0;
        for (uint32_t k = 0; k < info.numIncompatibleConnectors; k++) {
            NvKmsKapiConnector incompatible =
                info.incompatibleConnectorHandles[k];
            for (uint32_t j = 0; j < nv_dev->num_displays; j++) {
                if (i == j) {
                    continue;
                }
                if (nv_dev->display_connectors[j] == incompatible) {
                    mask |= (1U << j);
                }
            }
        }

        nv_dev->incompatible_display_mask[i] = mask;
        if (mask) {
            printk("nvidia_open: display[%u] incompatible mask=0x%x\n", i,
                   mask);
        }
    }
}

static bool nvidia_refresh_connector_modes(nvidia_device_t *nv_dev,
                                           drm_connector_t *connector,
                                           NvKmsKapiDisplay display,
                                           uint32_t *mm_width,
                                           uint32_t *mm_height) {
    if (!nv_dev || !connector) {
        return false;
    }

    struct drm_mode_modeinfo *new_modes = NULL;
    uint32_t mode_count = 0;
    uint32_t mode_capacity = 0;
    bool has_preferred = false;
    uint32_t pref_mm_width = 0;
    uint32_t pref_mm_height = 0;

    uint32_t mode_index = 0;
    while (true) {
        struct NvKmsKapiDisplayMode display_mode;
        NvBool valid = NV_FALSE;
        NvBool preferred = NV_FALSE;
        int ret = nvKms->getDisplayMode(nv_dev->kmsdev, display, mode_index++,
                                        &display_mode, &valid, &preferred);
        if (ret < 0) {
            free(new_modes);
            return false;
        }
        if (ret == 0) {
            break;
        }
        if (!valid) {
            continue;
        }

        if (mode_count == mode_capacity) {
            uint32_t next_capacity = mode_capacity ? mode_capacity * 2 : 8;
            struct drm_mode_modeinfo *grown_modes =
                realloc(new_modes, sizeof(*new_modes) * next_capacity);
            if (!grown_modes) {
                free(new_modes);
                return false;
            }
            new_modes = grown_modes;
            mode_capacity = next_capacity;
        }

        memset(&new_modes[mode_count], 0, sizeof(new_modes[mode_count]));
        nvidia_to_drm_mode(&display_mode, &new_modes[mode_count]);
        new_modes[mode_count].type = DRM_MODE_TYPE_DRIVER;

        if (preferred) {
            new_modes[mode_count].type |= DRM_MODE_TYPE_PREFERRED;
            pref_mm_width = display_mode.timings.widthMM;
            pref_mm_height = display_mode.timings.heightMM;
            has_preferred = true;
        }

        mode_count++;
    }

    if (!mode_count) {
        free(new_modes);
        return false;
    }

    if (!has_preferred) {
        new_modes[0].type |= DRM_MODE_TYPE_PREFERRED;
    }

    if (mm_width) {
        *mm_width = pref_mm_width;
    }
    if (mm_height) {
        *mm_height = pref_mm_height;
    }

    if (connector->modes) {
        free(connector->modes);
    }
    connector->modes = new_modes;
    connector->count_modes = mode_count;
    return true;
}

static void nvidia_update_display_connector_state(nvidia_device_t *nv_dev,
                                                  uint32_t display_idx) {
    if (!nv_dev || display_idx >= nv_dev->num_displays ||
        !nv_dev->connectors[display_idx]) {
        return;
    }

    drm_connector_t *connector = nv_dev->connectors[display_idx];
    NvKmsKapiDisplay display = nv_dev->displays[display_idx];
    uint32_t head = nv_dev->display_heads[display_idx];
    bool head_is_active =
        (head < NVKMS_KAPI_MAX_HEADS) ? nv_dev->head_active[head] : false;
    uint32_t old_connection = connector->connection;

    struct NvKmsKapiDynamicDisplayParams dyn_params;
    memset(&dyn_params, 0, sizeof(dyn_params));
    dyn_params.handle = display;
    bool dyn_info_valid =
        nvKms->getDynamicDisplayInfo(nv_dev->kmsdev, &dyn_params);

    uint32_t mm_width = 0;
    uint32_t mm_height = 0;
    if (!nvidia_refresh_connector_modes(nv_dev, connector, display, &mm_width,
                                        &mm_height)) {
        if (dyn_info_valid && !dyn_params.connected && !head_is_active) {
            connector->connection = DRM_MODE_DISCONNECTED;
        }
        return;
    }

    if (dyn_info_valid) {
        if (dyn_params.connected || head_is_active) {
            connector->connection = DRM_MODE_CONNECTED;
        } else {
            connector->connection = DRM_MODE_DISCONNECTED;
        }
    } else if (connector->connection != DRM_MODE_CONNECTED) {
        connector->connection = DRM_MODE_CONNECTED;
    }

    if (connector->connection == DRM_MODE_CONNECTED && display_idx < 32) {
        uint32_t incompat_mask = nv_dev->incompatible_display_mask[display_idx];
        for (uint32_t j = 0; j < nv_dev->num_displays; j++) {
            if (!(incompat_mask & (1U << j)) || !nv_dev->connectors[j] ||
                nv_dev->connectors[j]->connection != DRM_MODE_CONNECTED) {
                continue;
            }

            uint32_t peer_head = nv_dev->display_heads[j];
            bool peer_active = (peer_head < NVKMS_KAPI_MAX_HEADS)
                                   ? nv_dev->head_active[peer_head]
                                   : false;

            if (peer_active || (!head_is_active && j < display_idx)) {
                connector->connection = DRM_MODE_DISCONNECTED;
                break;
            }
        }
    }

    const struct drm_mode_modeinfo *preferred_mode =
        nvidia_preferred_connector_mode(connector);
    if (preferred_mode && display_idx < 16) {
        nv_dev->cached_modes[display_idx] = *preferred_mode;
        nv_dev->cached_mode_valid[display_idx] = true;
    }

    if (!mm_width && connector->modes[0].hdisplay) {
        mm_width = (connector->modes[0].hdisplay * 264UL) / 1000UL;
    }
    if (!mm_height && connector->modes[0].vdisplay) {
        mm_height = (connector->modes[0].vdisplay * 264UL) / 1000UL;
    }
    connector->mm_width = mm_width ? mm_width : 1;
    connector->mm_height = mm_height ? mm_height : 1;

    if (old_connection != connector->connection) {
        printk("nvidia_open: display=%u connector %s -> %s (active=%u)\n",
               display_idx,
               old_connection == DRM_MODE_CONNECTED ? "connected"
                                                    : "disconnected",
               connector->connection == DRM_MODE_CONNECTED ? "connected"
                                                           : "disconnected",
               head_is_active ? 1 : 0);
    }
}

static int nvidia_crtc_index_from_id(nvidia_device_t *nv_dev, uint32_t crtc_id,
                                     uint32_t *crtc_idx) {
    if (!nv_dev || !crtc_idx) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < nv_dev->num_crtcs; i++) {
        if (nv_dev->crtcs[i] && nv_dev->crtcs[i]->id == crtc_id) {
            *crtc_idx = i;
            return 0;
        }
    }

    return -ENOENT;
}

static int nvidia_crtc_index_from_display(nvidia_device_t *nv_dev,
                                          uint32_t display_idx,
                                          uint32_t *crtc_idx) {
    if (!nv_dev || !crtc_idx || display_idx >= nv_dev->num_displays) {
        return -EINVAL;
    }

    if (nv_dev->connectors[display_idx] &&
        nv_dev->connectors[display_idx]->crtc_id) {
        int ret = nvidia_crtc_index_from_id(
            nv_dev, nv_dev->connectors[display_idx]->crtc_id, crtc_idx);
        if (ret == 0) {
            return 0;
        }
    }

    if (nv_dev->encoders[display_idx] &&
        nv_dev->encoders[display_idx]->crtc_id) {
        int ret = nvidia_crtc_index_from_id(
            nv_dev, nv_dev->encoders[display_idx]->crtc_id, crtc_idx);
        if (ret == 0) {
            return 0;
        }
    }

    uint32_t head = nv_dev->display_heads[display_idx];
    if (head < NVKMS_KAPI_MAX_HEADS && nv_dev->head_to_crtc[head] >= 0) {
        uint32_t mapped = (uint32_t)nv_dev->head_to_crtc[head];
        if (mapped < nv_dev->num_crtcs && nv_dev->crtcs[mapped]) {
            *crtc_idx = mapped;
            return 0;
        }
    }

    return -ENOENT;
}

static int nvidia_display_index_from_crtc(nvidia_device_t *nv_dev,
                                          uint32_t crtc_id,
                                          uint32_t *display_idx) {
    if (!nv_dev || !display_idx) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (nv_dev->connectors[i] &&
            nv_dev->connectors[i]->crtc_id == crtc_id) {
            *display_idx = i;
            return 0;
        }
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (nv_dev->encoders[i] && nv_dev->encoders[i]->crtc_id == crtc_id) {
            *display_idx = i;
            return 0;
        }
    }

    uint32_t crtc_idx = 0;
    int ret = nvidia_crtc_index_from_id(nv_dev, crtc_id, &crtc_idx);
    if (ret != 0) {
        return ret;
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        uint32_t head = nv_dev->display_heads[i];
        if (head < NVKMS_KAPI_MAX_HEADS && nv_dev->head_to_crtc[head] >= 0 &&
            (uint32_t)nv_dev->head_to_crtc[head] == crtc_idx) {
            *display_idx = i;
            return 0;
        }
    }

    return -ENOENT;
}

static int nvidia_display_index_from_plane(nvidia_device_t *nv_dev,
                                           uint32_t plane_id,
                                           uint32_t *display_idx) {
    if (!nv_dev || !display_idx) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < nv_dev->num_crtcs; i++) {
        if (!nv_dev->planes[i] || nv_dev->planes[i]->id != plane_id) {
            continue;
        }

        uint32_t plane_crtc_id = nv_dev->planes[i]->crtc_id;
        if (!plane_crtc_id && nv_dev->crtcs[i]) {
            plane_crtc_id = nv_dev->crtcs[i]->id;
        }

        if (plane_crtc_id) {
            return nvidia_display_index_from_crtc(nv_dev, plane_crtc_id,
                                                  display_idx);
        }

        for (uint32_t display = 0; display < nv_dev->num_displays; display++) {
            uint32_t head = nv_dev->display_heads[display];
            if (head < NVKMS_KAPI_MAX_HEADS &&
                nv_dev->head_to_crtc[head] >= 0 &&
                (uint32_t)nv_dev->head_to_crtc[head] == i) {
                *display_idx = display;
                return 0;
            }
        }
    }

    return -ENOENT;
}

static int nvidia_display_index_from_connector(nvidia_device_t *nv_dev,
                                               uint32_t connector_id,
                                               uint32_t *display_idx) {
    if (!nv_dev || !display_idx) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (nv_dev->connectors[i] &&
            nv_dev->connectors[i]->id == connector_id) {
            *display_idx = i;
            return 0;
        }
    }

    return -ENOENT;
}

static int nvidia_validate_fb_id(nvidia_device_t *nv_dev, uint32_t fb_id) {
    if (!nv_dev) {
        return -EINVAL;
    }

    if (fb_id == 0) {
        return 0;
    }

    drm_framebuffer_t *drm_fb =
        drm_framebuffer_get(&nv_dev->resource_mgr, fb_id);
    if (!drm_fb) {
        return -ENOENT;
    }

    nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, drm_fb->handle);
    drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
    if (!nfb) {
        return -EINVAL;
    }

    return 0;
}

static void
nvidia_fill_layer_defaults(struct NvKmsKapiLayerRequestedConfig *layer) {
    if (!layer) {
        return;
    }

    layer->config.csc = NVKMS_IDENTITY_CSC_MATRIX;
    layer->config.rrParams.rotation = NVKMS_ROTATION_0;
    layer->config.minPresentInterval = 1;
    layer->config.tearing = NV_FALSE;
    layer->config.compParams.compMode = NVKMS_COMPOSITION_BLENDING_MODE_OPAQUE;
    layer->config.inputColorSpace = NVKMS_INPUT_COLOR_SPACE_NONE;
    layer->config.inputColorRange = NVKMS_INPUT_COLOR_RANGE_DEFAULT;
    layer->config.inputTf = NVKMS_INPUT_TF_LINEAR;
    layer->config.outputTf = NVKMS_OUTPUT_TF_NONE;
    layer->config.hdrMetadata.enabled = NV_FALSE;
    layer->config.syncParams.preSyncptSpecified = NV_FALSE;
    layer->config.syncParams.postSyncptRequested = NV_FALSE;
    layer->config.syncParams.semaphoreSpecified = NV_FALSE;
}

static int nvidia_gpu_index(nvidia_device_t *nv_dev) {
    if (!nv_dev) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < nvidia_gpu_count && i < MAX_NVIDIA_GPU_NUM; i++) {
        if (nvidia_gpus[i] == nv_dev) {
            return (int)i;
        }
    }

    return -ENOENT;
}

static int nvidia_fb_index(const nvidia_fb_t *fb) {
    if (!fb || !fb->handle || fb->handle > 32) {
        return -EINVAL;
    }

    return (int)(fb->handle - 1);
}

static uint64_t nvidia_pages_for_size(uint64_t size) {
    return (size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE;
}

static int nvidia_validate_fb_geometry(const nvidia_fb_t *fb, uint32_t width,
                                       uint32_t height, uint32_t pitch) {
    if (!fb || !width || !height || !pitch) {
        return -EINVAL;
    }

    uint64_t required = (uint64_t)pitch * (uint64_t)height;
    if (required == 0 || required > fb->size) {
        return -EINVAL;
    }

    return 0;
}

static int nvidia_sync_shadow_to_scanout(nvidia_device_t *nv_dev,
                                         nvidia_fb_t *fb) {
    if (!nv_dev || !fb || !fb->memory || !fb->map_offset || !fb->size) {
        return -EINVAL;
    }

    int gpu_idx = nvidia_gpu_index(nv_dev);
    int fb_idx = nvidia_fb_index(fb);
    if (gpu_idx < 0 || fb_idx < 0) {
        return -ENODEV;
    }

    void *scanout = nvidia_scanout_maps[gpu_idx][fb_idx];
    if (!scanout) {
        if (!nvKms->mapMemory(nv_dev->kmsdev, fb->memory,
                              NVKMS_KAPI_MAPPING_TYPE_KERNEL, &scanout)) {
            return -EIO;
        }
        nvidia_scanout_maps[gpu_idx][fb_idx] = scanout;
    }

    memcpy(scanout, (void *)(uintptr_t)phys_to_virt(fb->map_offset), fb->size);
    return 0;
}

static int nvidia_ensure_surface(nvidia_device_t *nv_dev, nvidia_fb_t *fb,
                                 uint32_t fourcc, uint32_t width,
                                 uint32_t height, uint32_t pitch,
                                 uint64_t modifier) {
    if (!nv_dev || !fb || !fb->memory || !width || !height || !pitch) {
        return -EINVAL;
    }

    enum NvKmsSurfaceMemoryFormat format;
    if (!nvidia_drm_to_surface_format(fourcc, &format)) {
        return -EINVAL;
    }

    struct NvKmsKapiCreateSurfaceParams params;
    memset(&params, 0, sizeof(params));

    params.planes[0].memory = fb->memory;
    params.planes[0].offset = 0;
    params.planes[0].pitch = pitch;
    params.width = width;
    params.height = height;
    params.format = format;
    params.noDisplayCaching = NV_TRUE;

    if (modifier == 0) {
        params.explicit_layout = NV_FALSE;
    } else {
        params.explicit_layout = NV_TRUE;
        params.layout = (modifier & 0x10) ? NvKmsSurfaceMemoryLayoutBlockLinear
                                          : NvKmsSurfaceMemoryLayoutPitch;

        if (params.layout == NvKmsSurfaceMemoryLayoutBlockLinear &&
            ((modifier >> 23) & 0x7)) {
            return -EINVAL;
        }

        params.log2GobsPerBlockY = modifier & 0xF;
    }

    if (fb->surface) {
        nvKms->destroySurface(nv_dev->kmsdev, fb->surface);
        fb->surface = NULL;
    }

    fb->surface = nvKms->createSurface(nv_dev->kmsdev, &params);
    if (!fb->surface) {
        return -EIO;
    }

    fb->format = fourcc;
    fb->modifier = modifier;
    fb->width = width;
    fb->height = height;
    fb->pitch = pitch;
    return 0;
}

static int nvidia_validate_display_mode(nvidia_device_t *nv_dev,
                                        uint32_t display_idx,
                                        const struct drm_mode_modeinfo *mode) {
    if (!nv_dev || display_idx >= nv_dev->num_displays || !mode) {
        return -EINVAL;
    }

    struct NvKmsKapiDisplayMode kapi_mode;
    memset(&kapi_mode, 0, sizeof(kapi_mode));
    nvidia_to_kapi_mode(mode, &kapi_mode);

    if (!nvKms->validateDisplayMode(
            nv_dev->kmsdev, nv_dev->displays[display_idx], &kapi_mode)) {
        return -EINVAL;
    }

    return 0;
}

static int nvidia_apply_modeset(nvidia_device_t *nv_dev, uint32_t display_idx,
                                nvidia_fb_t *fb,
                                const struct drm_mode_modeinfo *mode,
                                bool mode_changed, bool send_flip_event,
                                bool commit, uint64_t user_data, uint32_t x,
                                uint32_t y, uint32_t width, uint32_t height,
                                uint32_t src_x, uint32_t src_y,
                                uint32_t src_width, uint32_t src_height) {
    if (!nv_dev || display_idx >= nv_dev->num_displays) {
        return -EINVAL;
    }

    uint32_t head = nv_dev->display_heads[display_idx];
    if (head >= NVKMS_KAPI_MAX_HEADS) {
        return -EINVAL;
    }

    struct NvKmsKapiRequestedModeSetConfig req;
    struct NvKmsKapiModeSetReplyConfig reply;
    memset(&req, 0, sizeof(req));
    memset(&reply, 0, sizeof(reply));

    req.headsMask = 1U << head;

    struct NvKmsKapiHeadRequestedConfig *head_cfg =
        &req.headRequestedConfig[head];
    head_cfg->modeSetConfig.vrrEnabled = NV_FALSE;
    head_cfg->modeSetConfig.olutFpNormScale = NVKMS_OLUT_FP_NORM_SCALE_DEFAULT;

    uint32_t crtc_idx = 0;
    int crtc_ret =
        nvidia_crtc_index_from_display(nv_dev, display_idx, &crtc_idx);
    bool has_crtc = (crtc_ret == 0 && crtc_idx < nv_dev->num_crtcs &&
                     nv_dev->crtcs[crtc_idx]);
    bool current_active = nv_dev->head_active[head];
    bool requested_active = (fb != NULL);

    head_cfg->flags.activeChanged =
        (requested_active != current_active) ? NV_TRUE : NV_FALSE;
    head_cfg->flags.displaysChanged =
        (requested_active != current_active) ? NV_TRUE : NV_FALSE;

    const struct drm_mode_modeinfo *effective_mode = mode;
    struct drm_mode_modeinfo queried_mode;
    bool queried_mode_valid = false;
    struct NvKmsKapiDisplayMode requested_kapi_mode;
    bool requested_kapi_mode_valid = false;
    bool reused_cached_kapi_mode = false;

    if (!effective_mode && requested_active) {
        if (has_crtc && nv_dev->crtcs[crtc_idx]->mode_valid) {
            effective_mode = &nv_dev->crtcs[crtc_idx]->mode;
        }
    }

    if (!effective_mode && requested_active && display_idx < 16 &&
        nv_dev->cached_mode_valid[display_idx]) {
        effective_mode = &nv_dev->cached_modes[display_idx];
    }

    if (!effective_mode && requested_active &&
        nv_dev->connectors[display_idx]) {
        effective_mode =
            nvidia_preferred_connector_mode(nv_dev->connectors[display_idx]);
    }

    if (!effective_mode && requested_active) {
        struct NvKmsKapiDisplayMode kapi_mode;
        memset(&kapi_mode, 0, sizeof(kapi_mode));
        if (nvidia_get_display_mode(nv_dev, nv_dev->displays[display_idx],
                                    &kapi_mode, NULL, NULL)) {
            memset(&queried_mode, 0, sizeof(queried_mode));
            nvidia_to_drm_mode(&kapi_mode, &queried_mode);
            effective_mode = &queried_mode;
            queried_mode_valid = true;
            if (display_idx < 16) {
                nv_dev->cached_modes[display_idx] = queried_mode;
                nv_dev->cached_mode_valid[display_idx] = true;
            }
        }
    }

    if (effective_mode) {
        memset(&requested_kapi_mode, 0, sizeof(requested_kapi_mode));
        nvidia_to_kapi_mode(effective_mode, &requested_kapi_mode);
        requested_kapi_mode_valid = true;
    } else if (requested_active && display_idx < 16 &&
               nv_dev->cached_kapi_mode_valid[display_idx]) {
        requested_kapi_mode = nv_dev->cached_kapi_modes[display_idx];
        requested_kapi_mode_valid = true;
        reused_cached_kapi_mode = true;
    }

    bool effective_mode_changed =
        mode_changed || (requested_active && !current_active);
    if (effective_mode_changed && !requested_kapi_mode_valid) {
        effective_mode_changed = false;
    }
    if (requested_active && !requested_kapi_mode_valid) {
        uint32_t connector_modes = 0;
        if (nv_dev->connectors[display_idx]) {
            connector_modes = nv_dev->connectors[display_idx]->count_modes;
        }
        printk("nvidia_open: no mode selected for display=%u (crtc_valid=%u "
               "cached_valid=%u cached_kapi_valid=%u connector_modes=%u)\n",
               display_idx,
               (crtc_idx < nv_dev->num_crtcs && nv_dev->crtcs[crtc_idx])
                   ? nv_dev->crtcs[crtc_idx]->mode_valid
                   : 0,
               (display_idx < 16 && nv_dev->cached_mode_valid[display_idx]) ? 1
                                                                            : 0,
               (display_idx < 16 && nv_dev->cached_kapi_mode_valid[display_idx])
                   ? 1
                   : 0,
               connector_modes);
    }
    head_cfg->flags.modeChanged = effective_mode_changed ? NV_TRUE : NV_FALSE;

    if (fb && commit) {
        int sync_ret = nvidia_sync_shadow_to_scanout(nv_dev, fb);
        if (sync_ret != 0) {
            return sync_ret;
        }
    }

    if (head_cfg->flags.activeChanged) {
        head_cfg->modeSetConfig.bActive = requested_active ? NV_TRUE : NV_FALSE;
    }

    if (head_cfg->flags.displaysChanged) {
        if (requested_active) {
            head_cfg->modeSetConfig.numDisplays = 1;
            head_cfg->modeSetConfig.displays[0] = nv_dev->displays[display_idx];
        } else {
            head_cfg->modeSetConfig.numDisplays = 0;
        }
    }

    if (head_cfg->flags.modeChanged && requested_kapi_mode_valid) {
        head_cfg->modeSetConfig.mode = requested_kapi_mode;
    }

    if (requested_active && requested_kapi_mode_valid) {
        if (effective_mode) {
            int valid_ret = nvidia_validate_display_mode(nv_dev, display_idx,
                                                         effective_mode);
            if (valid_ret != 0) {
                return valid_ret;
            }
        } else if (!nvKms->validateDisplayMode(nv_dev->kmsdev,
                                               nv_dev->displays[display_idx],
                                               &requested_kapi_mode)) {
            return -EINVAL;
        }
    }

    for (uint32_t layer = 0; layer < NVKMS_KAPI_LAYER_MAX; layer++) {
        nvidia_fill_layer_defaults(&head_cfg->layerRequestedConfig[layer]);
    }

    struct NvKmsKapiLayerRequestedConfig *primary =
        &head_cfg->layerRequestedConfig[NVKMS_KAPI_LAYER_PRIMARY_IDX];

    if (fb) {
        uint16_t cfg_src_x = (uint16_t)src_x;
        uint16_t cfg_src_y = (uint16_t)src_y;
        uint16_t cfg_src_w =
            (uint16_t)(src_width ? src_width : (width ? width : fb->width));
        uint16_t cfg_src_h =
            (uint16_t)(src_height ? src_height
                                  : (height ? height : fb->height));
        int16_t cfg_dst_x = (int16_t)x;
        int16_t cfg_dst_y = (int16_t)y;
        uint16_t cfg_dst_w = (uint16_t)(width ? width : fb->width);
        uint16_t cfg_dst_h = (uint16_t)(height ? height : fb->height);

        if ((uint32_t)cfg_src_x + (uint32_t)cfg_src_w > fb->width) {
            cfg_src_x = 0;
            cfg_src_w = (uint16_t)fb->width;
        }
        if ((uint32_t)cfg_src_y + (uint32_t)cfg_src_h > fb->height) {
            cfg_src_y = 0;
            cfg_src_h = (uint16_t)fb->height;
        }

        primary->config.surface = fb->surface;
        primary->config.srcX = cfg_src_x;
        primary->config.srcY = cfg_src_y;
        primary->config.srcWidth = cfg_src_w;
        primary->config.srcHeight = cfg_src_h;
        primary->config.dstX = cfg_dst_x;
        primary->config.dstY = cfg_dst_y;
        primary->config.dstWidth = cfg_dst_w;
        primary->config.dstHeight = cfg_dst_h;
        primary->flags.surfaceChanged = NV_TRUE;
        if (nv_dev->primary_state_valid[head]) {
            primary->flags.srcXYChanged =
                (nv_dev->primary_src_x[head] != cfg_src_x) ||
                (nv_dev->primary_src_y[head] != cfg_src_y);
            primary->flags.srcWHChanged =
                (nv_dev->primary_src_w[head] != cfg_src_w) ||
                (nv_dev->primary_src_h[head] != cfg_src_h);
            primary->flags.dstXYChanged =
                (nv_dev->primary_dst_x[head] != cfg_dst_x) ||
                (nv_dev->primary_dst_y[head] != cfg_dst_y);
            primary->flags.dstWHChanged =
                (nv_dev->primary_dst_w[head] != cfg_dst_w) ||
                (nv_dev->primary_dst_h[head] != cfg_dst_h);
        } else {
            primary->flags.srcXYChanged = NV_TRUE;
            primary->flags.srcWHChanged = NV_TRUE;
            primary->flags.dstXYChanged = NV_TRUE;
            primary->flags.dstWHChanged = NV_TRUE;
        }
    } else {
        memset(primary, 0, sizeof(*primary));
        nvidia_fill_layer_defaults(primary);
        primary->flags.surfaceChanged = NV_TRUE;
        primary->flags.srcXYChanged =
            nv_dev->primary_state_valid[head] ? NV_TRUE : NV_FALSE;
        primary->flags.srcWHChanged =
            nv_dev->primary_state_valid[head] ? NV_TRUE : NV_FALSE;
        primary->flags.dstXYChanged =
            nv_dev->primary_state_valid[head] ? NV_TRUE : NV_FALSE;
        primary->flags.dstWHChanged =
            nv_dev->primary_state_valid[head] ? NV_TRUE : NV_FALSE;
    }

    if (send_flip_event && commit) {
        nv_dev->pending_flip_user_data[head] = user_data;
        nv_dev->pending_flip_event[head] = true;
    }

    if (!nvKms->applyModeSetConfig(nv_dev->kmsdev, &req, &reply,
                                   commit ? NV_TRUE : NV_FALSE)) {
        printk("nvidia_open: applyModeSetConfig failed display=%u head=%u "
               "active=%u mode_changed=%u fb=%u flipResult=%d src=%u,%u %ux%u "
               "dst=%d,%d %ux%u\n",
               display_idx, head, requested_active ? 1 : 0,
               effective_mode_changed ? 1 : 0, fb ? fb->fb_id : 0,
               reply.flipResult, primary->config.srcX, primary->config.srcY,
               primary->config.srcWidth, primary->config.srcHeight,
               primary->config.dstX, primary->config.dstY,
               primary->config.dstWidth, primary->config.dstHeight);
        if (!requested_kapi_mode_valid && requested_active) {
            printk("nvidia_open: no usable mode for active display=%u\n",
                   display_idx);
        } else if (queried_mode_valid) {
            printk("nvidia_open: queried mode %ux%u@%u used for display=%u\n",
                   queried_mode.hdisplay, queried_mode.vdisplay,
                   queried_mode.vrefresh, display_idx);
        } else if (reused_cached_kapi_mode) {
            printk("nvidia_open: reused cached KAPI mode for display=%u\n",
                   display_idx);
        }
        if (send_flip_event && commit) {
            nv_dev->pending_flip_event[head] = false;
        }
        if (reply.flipResult == NV_KMS_FLIP_RESULT_IN_PROGRESS) {
            return -EBUSY;
        }
        if (reply.flipResult == NV_KMS_FLIP_RESULT_INVALID_PARAMS) {
            return -EINVAL;
        }
        return -EIO;
    }

    if (requested_active && requested_kapi_mode_valid && display_idx < 16) {
        nv_dev->cached_kapi_modes[display_idx] = requested_kapi_mode;
        nv_dev->cached_kapi_mode_valid[display_idx] = true;

        if (effective_mode) {
            nv_dev->cached_modes[display_idx] = *effective_mode;
            nv_dev->cached_mode_valid[display_idx] = true;
        } else {
            struct drm_mode_modeinfo cached_mode;
            memset(&cached_mode, 0, sizeof(cached_mode));
            nvidia_to_drm_mode(&requested_kapi_mode, &cached_mode);
            nv_dev->cached_modes[display_idx] = cached_mode;
            nv_dev->cached_mode_valid[display_idx] = true;
        }
    }

    if (send_flip_event && commit && nv_dev->drm_dev) {
        drm_post_event(nv_dev->drm_dev, DRM_EVENT_FLIP_COMPLETE, user_data);
        nv_dev->pending_flip_event[head] = false;
        nv_dev->pending_flip_user_data[head] = 0;
    }

    if (commit) {
        nv_dev->head_active[head] = requested_active;
        if (requested_active && fb) {
            nv_dev->primary_state_valid[head] = true;
            nv_dev->primary_src_x[head] = primary->config.srcX;
            nv_dev->primary_src_y[head] = primary->config.srcY;
            nv_dev->primary_src_w[head] = primary->config.srcWidth;
            nv_dev->primary_src_h[head] = primary->config.srcHeight;
            nv_dev->primary_dst_x[head] = primary->config.dstX;
            nv_dev->primary_dst_y[head] = primary->config.dstY;
            nv_dev->primary_dst_w[head] = primary->config.dstWidth;
            nv_dev->primary_dst_h[head] = primary->config.dstHeight;
        } else {
            nv_dev->primary_state_valid[head] = false;
        }
    }

    return 0;
}

int nvidia_get_display_info(drm_device_t *drm_dev, uint32_t *width,
                            uint32_t *height, uint32_t *bpp) {
    if (!drm_dev || !width || !height || !bpp) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = (nvidia_device_t *)drm_dev->data;
    if (nv_dev && nv_dev->num_displays > 0 && nv_dev->connectors[0] &&
        nv_dev->connectors[0]->count_modes && nv_dev->connectors[0]->modes) {
        const struct drm_mode_modeinfo *mode =
            nvidia_preferred_connector_mode(nv_dev->connectors[0]);
        if (mode) {
            *width = mode->hdisplay;
            *height = mode->vdisplay;
            *bpp = 32;
            return 0;
        }
    }

    boot_framebuffer_t *fb = get_current_fb();
    if (!fb) {
        return -ENODEV;
    }

    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;
    return 0;
}

int nvidia_get_fb(drm_device_t *drm_dev, uint32_t *width, uint32_t *height,
                  uint32_t *bpp, uint64_t *addr) {
    if (!drm_dev || !width || !height || !bpp || !addr) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = (nvidia_device_t *)drm_dev->data;
    if (nv_dev) {
        for (uint32_t i = 0; i < nv_dev->num_crtcs; i++) {
            drm_crtc_t *crtc = nv_dev->crtcs[i];
            if (!crtc || !crtc->fb_id) {
                continue;
            }

            nvidia_fb_t *nfb = nvidia_fb_by_fb_id(nv_dev, crtc->fb_id);
            if (nfb) {
                *width = nfb->width;
                *height = nfb->height;
                *bpp = nfb->bpp ? nfb->bpp : 32;
                *addr = nfb->map_offset;
                return 0;
            }
        }
    }

    boot_framebuffer_t *fb = get_current_fb();
    if (!fb) {
        return -ENODEV;
    }

    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;
    *addr = (uint64_t)fb->address;
    return 0;
}

int nvidia_create_dumb(drm_device_t *drm_dev,
                       struct drm_mode_create_dumb *args) {
    if (!drm_dev || !args || args->width == 0 || args->height == 0) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    if (args->bpp == 0) {
        args->bpp = 32;
    }

    int gpu_idx = nvidia_gpu_index(nv_dev);
    if (gpu_idx < 0) {
        return -ENODEV;
    }

    uint32_t bytes_per_pixel = (args->bpp + 7) >> 3;
    if (!bytes_per_pixel) {
        return -EINVAL;
    }

    uint32_t alignment = nv_dev->pitch_alignment ? nv_dev->pitch_alignment : 64;
    args->pitch =
        ((args->width * bytes_per_pixel + alignment - 1) / alignment) *
        alignment;
    args->size = (uint64_t)args->pitch * args->height;
    args->size = (args->size + 0xFFFULL) & ~0xFFFULL;

    for (uint32_t i = 0; i < 32; i++) {
        nvidia_fb_t *fb = &nv_dev->framebuffers[i];
        if (fb->in_use) {
            continue;
        }

        NvU8 compressible = 0;
        struct NvKmsKapiMemory *memory = NULL;
        if (nv_dev->has_video_memory) {
            memory = nvKms->allocateVideoMemory(
                nv_dev->kmsdev, NvKmsSurfaceMemoryLayoutPitch,
                NVKMS_KAPI_ALLOCATION_TYPE_SCANOUT, args->size, &compressible);
        } else {
            memory = nvKms->allocateSystemMemory(
                nv_dev->kmsdev, NvKmsSurfaceMemoryLayoutPitch,
                NVKMS_KAPI_ALLOCATION_TYPE_SCANOUT, args->size, &compressible);
        }

        if (!memory) {
            return -ENOMEM;
        }

        uint64_t page_count = nvidia_pages_for_size(args->size);
        uintptr_t shadow_phys = alloc_frames(page_count);
        if (!shadow_phys) {
            nvKms->freeMemory(nv_dev->kmsdev, memory);
            return -ENOMEM;
        }

        memset((void *)(uintptr_t)phys_to_virt(shadow_phys), 0,
               page_count * DEFAULT_PAGE_SIZE);

        void *scanout_map = NULL;
        if (!nvKms->mapMemory(nv_dev->kmsdev, memory,
                              NVKMS_KAPI_MAPPING_TYPE_KERNEL, &scanout_map)) {
            free_frames(shadow_phys, page_count);
            nvKms->freeMemory(nv_dev->kmsdev, memory);
            return -EIO;
        }

        memset(fb, 0, sizeof(*fb));
        fb->in_use = true;
        fb->handle = i + 1;
        fb->width = args->width;
        fb->height = args->height;
        fb->pitch = args->pitch;
        fb->bpp = args->bpp;
        fb->size = args->size;
        fb->map_offset = (uint64_t)shadow_phys;
        fb->refcount = 1;
        fb->memory = memory;
        fb->format = DRM_FORMAT_XRGB8888;
        nvidia_scanout_maps[gpu_idx][i] = scanout_map;

        args->handle = fb->handle;
        return 0;
    }

    return -ENOSPC;
}

int nvidia_destroy_dumb(drm_device_t *drm_dev, uint32_t handle) {
    if (!drm_dev) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    nvidia_fb_t *fb = nvidia_fb_by_handle(nv_dev, handle);
    if (!fb) {
        return -EINVAL;
    }

    if (fb->refcount > 0) {
        fb->refcount--;
    }

    if (fb->refcount != 0) {
        return 0;
    }

    int gpu_idx = nvidia_gpu_index(nv_dev);
    int fb_idx = nvidia_fb_index(fb);
    if (gpu_idx >= 0 && fb_idx >= 0 && fb->memory &&
        nvidia_scanout_maps[gpu_idx][fb_idx]) {
        nvKms->unmapMemory(nv_dev->kmsdev, fb->memory,
                           NVKMS_KAPI_MAPPING_TYPE_KERNEL,
                           nvidia_scanout_maps[gpu_idx][fb_idx]);
        nvidia_scanout_maps[gpu_idx][fb_idx] = NULL;
    }

    if (fb->surface) {
        nvKms->destroySurface(nv_dev->kmsdev, fb->surface);
    }
    if (fb->map_offset && fb->size) {
        free_frames((uintptr_t)fb->map_offset, nvidia_pages_for_size(fb->size));
    }
    if (fb->memory) {
        nvKms->freeMemory(nv_dev->kmsdev, fb->memory);
    }

    memset(fb, 0, sizeof(*fb));
    return 0;
}

int nvidia_dirty_fb(drm_device_t *drm_dev, struct drm_mode_fb_dirty_cmd *cmd) {
    (void)drm_dev;
    (void)cmd;
    return 0;
}

int nvidia_add_fb(drm_device_t *drm_dev, struct drm_mode_fb_cmd *cmd) {
    if (!drm_dev || !cmd || !cmd->handle || !cmd->width || !cmd->height ||
        !cmd->pitch) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, cmd->handle);
    if (!nfb) {
        return -EINVAL;
    }
    if (nvidia_validate_fb_geometry(nfb, cmd->width, cmd->height, cmd->pitch) !=
        0) {
        return -EINVAL;
    }

    uint32_t fourcc = 0;
    uint32_t bpp = 0;
    uint32_t depth = 0;
    int ret = nvidia_legacy_fb_to_drm_format(cmd->bpp, cmd->depth, &fourcc,
                                             &bpp, &depth);
    if (ret != 0) {
        return ret;
    }

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&nv_dev->resource_mgr, nv_dev);
    if (!fb) {
        return -ENOMEM;
    }

    fb->width = cmd->width;
    fb->height = cmd->height;
    fb->pitch = cmd->pitch;
    fb->bpp = bpp;
    fb->depth = depth;
    fb->handle = cmd->handle;
    fb->format = fourcc;
    fb->modifier = 0;
    fb->flags = 0;
    cmd->fb_id = fb->id;

    ret = nvidia_ensure_surface(nv_dev, nfb, fb->format, fb->width, fb->height,
                                fb->pitch, 0);
    if (ret != 0) {
        drm_framebuffer_free(&nv_dev->resource_mgr, fb->id);
        return ret;
    }

    nfb->fb_id = fb->id;
    nfb->bpp = fb->bpp;

    return 0;
}

int nvidia_add_fb2(drm_device_t *drm_dev, struct drm_mode_fb_cmd2 *cmd) {
    if (!drm_dev || !cmd || cmd->handles[0] == 0 || !cmd->width ||
        !cmd->height) {
        return -EINVAL;
    }

    if (cmd->flags & ~DRM_MODE_FB_MODIFIERS) {
        return -EINVAL;
    }

    for (uint32_t i = 1; i < 4; i++) {
        if (cmd->handles[i] || cmd->pitches[i] || cmd->offsets[i] ||
            cmd->modifier[i]) {
            return -EINVAL;
        }
    }

    if (cmd->offsets[0]) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, cmd->handles[0]);
    if (!nfb) {
        return -EINVAL;
    }

    uint32_t pitch = cmd->pitches[0] ? cmd->pitches[0] : nfb->pitch;
    if (nvidia_validate_fb_geometry(nfb, cmd->width, cmd->height, pitch) != 0) {
        return -EINVAL;
    }

    uint32_t bpp = 0;
    uint32_t depth = 0;
    if (nvidia_fb_format_to_depth(cmd->pixel_format, &bpp, &depth) != 0) {
        return -EINVAL;
    }

    uint64_t modifier =
        (cmd->flags & DRM_MODE_FB_MODIFIERS) ? cmd->modifier[0] : 0;

    drm_framebuffer_t *fb =
        drm_framebuffer_alloc(&nv_dev->resource_mgr, nv_dev);
    if (!fb) {
        return -ENOMEM;
    }

    fb->width = cmd->width;
    fb->height = cmd->height;
    fb->pitch = pitch;
    fb->bpp = bpp;
    fb->depth = depth;
    fb->handle = cmd->handles[0];
    fb->format = cmd->pixel_format;
    fb->modifier = modifier;
    fb->flags = cmd->flags;
    cmd->fb_id = fb->id;

    int ret = nvidia_ensure_surface(nv_dev, nfb, fb->format, fb->width,
                                    fb->height, fb->pitch, fb->modifier);
    if (ret != 0) {
        drm_framebuffer_free(&nv_dev->resource_mgr, fb->id);
        return ret;
    }

    nfb->fb_id = fb->id;
    nfb->bpp = fb->bpp;

    return 0;
}

int nvidia_set_plane(drm_device_t *drm_dev, struct drm_mode_set_plane *plane) {
    if (!drm_dev || !plane) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    drm_plane_t *drm_plane =
        drm_plane_get(&nv_dev->resource_mgr, plane->plane_id);
    if (!drm_plane) {
        return -ENOENT;
    }

    drm_plane->crtc_id = plane->crtc_id;
    drm_plane->fb_id = plane->fb_id;

    drm_plane_free(&nv_dev->resource_mgr, drm_plane->id);

    if (plane->fb_id == 0) {
        struct drm_mode_crtc crtc_req = {
            .crtc_id = plane->crtc_id,
            .fb_id = 0,
            .x = plane->crtc_x,
            .y = plane->crtc_y,
            .mode_valid = 0,
        };
        return nvidia_set_crtc(drm_dev, &crtc_req);
    }

    struct drm_mode_crtc_page_flip flip = {
        .crtc_id = plane->crtc_id,
        .fb_id = plane->fb_id,
        .flags = 0,
        .reserved = 0,
        .user_data = 0,
    };

    return nvidia_page_flip(drm_dev, &flip);
}

int nvidia_atomic_commit(drm_device_t *drm_dev,
                         struct drm_mode_atomic *atomic) {
    if (!drm_dev || !atomic) {
        return -EINVAL;
    }

    if (atomic->flags & ~DRM_MODE_ATOMIC_FLAGS) {
        return -EINVAL;
    }

    if ((atomic->flags & DRM_MODE_ATOMIC_TEST_ONLY) &&
        (atomic->flags & DRM_MODE_PAGE_FLIP_EVENT)) {
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

    nvidia_device_t *nv_dev = drm_dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    bool test_only = !!(atomic->flags & DRM_MODE_ATOMIC_TEST_ONLY);

    struct nvidia_atomic_display_state {
        bool touched;
        bool active;
        bool mode_valid;
        bool mode_changed;
        struct drm_mode_modeinfo mode;
        uint32_t x;
        uint32_t y;
        uint32_t w;
        uint32_t h;
        uint32_t src_x;
        uint32_t src_y;
        uint32_t src_w;
        uint32_t src_h;
        uint32_t fb_id;
        uint32_t connector_crtc_id;
    } states[16];
    memset(states, 0, sizeof(states));

    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        uint32_t crtc_idx = 0;
        drm_crtc_t *crtc = NULL;
        drm_plane_t *plane = NULL;
        if (nvidia_crtc_index_from_display(nv_dev, i, &crtc_idx) == 0) {
            crtc = nv_dev->crtcs[crtc_idx];
            plane = nv_dev->planes[crtc_idx];
        }
        drm_connector_t *connector = nv_dev->connectors[i];

        states[i].touched = false;
        uint32_t initial_fb_id =
            plane && plane->fb_id ? plane->fb_id : (crtc ? crtc->fb_id : 0);
        states[i].active = initial_fb_id != 0;
        states[i].mode_valid = crtc ? !!crtc->mode_valid : false;
        states[i].mode_changed = false;
        states[i].mode = crtc ? crtc->mode : (struct drm_mode_modeinfo){0};
        states[i].x = crtc ? crtc->x : 0;
        states[i].y = crtc ? crtc->y : 0;
        states[i].w = crtc ? crtc->w : 0;
        states[i].h = crtc ? crtc->h : 0;
        states[i].src_x = 0;
        states[i].src_y = 0;
        states[i].src_w = states[i].w;
        states[i].src_h = states[i].h;
        states[i].fb_id = initial_fb_id;
        states[i].connector_crtc_id =
            connector ? connector->crtc_id : (crtc ? crtc->id : 0);
    }

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
            case DRM_PROPERTY_ID_CRTC_ID:
            case DRM_PROPERTY_ID_CRTC_X:
            case DRM_PROPERTY_ID_CRTC_Y:
            case DRM_PROPERTY_ID_CRTC_W:
            case DRM_PROPERTY_ID_CRTC_H:
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
        uint32_t display_idx = 0;
        int ret = 0;

        if (obj_type == ATOMIC_OBJ_PLANE) {
            plane = drm_plane_get(&nv_dev->resource_mgr, obj_id);
            if (!plane) {
                return -ENOENT;
            }
            ret = nvidia_display_index_from_plane(nv_dev, obj_id, &display_idx);
            if (ret != 0) {
                drm_plane_free(&nv_dev->resource_mgr, plane->id);
                if (ret == -ENOENT) {
                    prop_idx += count;
                    continue;
                }
                return ret;
            }
        } else if (obj_type == ATOMIC_OBJ_CRTC) {
            crtc = drm_crtc_get(&nv_dev->resource_mgr, obj_id);
            if (!crtc) {
                return -ENOENT;
            }
            ret = nvidia_display_index_from_crtc(nv_dev, obj_id, &display_idx);
            if (ret != 0) {
                drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                if (ret == -ENOENT) {
                    prop_idx += count;
                    continue;
                }
                return ret;
            }
        } else if (obj_type == ATOMIC_OBJ_CONNECTOR) {
            connector = drm_connector_get(&nv_dev->resource_mgr, obj_id);
            if (!connector) {
                return -ENOENT;
            }
            ret = nvidia_display_index_from_connector(nv_dev, obj_id,
                                                      &display_idx);
            if (ret != 0) {
                drm_connector_free(&nv_dev->resource_mgr, connector->id);
                if (ret == -ENOENT) {
                    prop_idx += count;
                    continue;
                }
                return ret;
            }
        } else {
            prop_idx += count;
            continue;
        }

        int plane_target_display = (int)display_idx;
        uint32_t plane_fb_id = states[display_idx].fb_id;
        bool plane_x_set = false, plane_y_set = false, plane_w_set = false,
             plane_h_set = false;
        bool plane_src_x_set = false, plane_src_y_set = false,
             plane_src_w_set = false, plane_src_h_set = false;
        uint32_t plane_x = states[display_idx].x;
        uint32_t plane_y = states[display_idx].y;
        uint32_t plane_w = states[display_idx].w;
        uint32_t plane_h = states[display_idx].h;
        uint32_t plane_src_x = states[display_idx].src_x;
        uint32_t plane_src_y = states[display_idx].src_y;
        uint32_t plane_src_w = states[display_idx].src_w;
        uint32_t plane_src_h = states[display_idx].src_h;

        for (uint32_t j = 0; j < count; j++, prop_idx++) {
            uint32_t prop_id = prop_ids[prop_idx];
            uint64_t value = prop_values[prop_idx];

            switch (prop_id) {
            case DRM_PROPERTY_ID_PLANE_TYPE:
                if (!plane || value != plane->plane_type) {
                    if (connector) {
                        drm_connector_free(&nv_dev->resource_mgr,
                                           connector->id);
                    }
                    if (crtc) {
                        drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                    }
                    if (plane) {
                        drm_plane_free(&nv_dev->resource_mgr, plane->id);
                    }
                    return -EINVAL;
                }
                break;

            case DRM_PROPERTY_ID_FB_ID:
                if (plane) {
                    int fb_ret = nvidia_validate_fb_id(nv_dev, (uint32_t)value);
                    if (fb_ret != 0) {
                        if (connector) {
                            drm_connector_free(&nv_dev->resource_mgr,
                                               connector->id);
                        }
                        if (crtc) {
                            drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                        }
                        if (plane) {
                            drm_plane_free(&nv_dev->resource_mgr, plane->id);
                        }
                        return fb_ret;
                    }
                    plane_fb_id = (uint32_t)value;
                }
                break;

            case DRM_PROPERTY_ID_CRTC_ID:
                if (plane) {
                    if (value == 0) {
                        plane_target_display = -1;
                    } else {
                        uint32_t target_display = 0;
                        int crtc_ret = nvidia_display_index_from_crtc(
                            nv_dev, (uint32_t)value, &target_display);
                        if (crtc_ret != 0) {
                            if (crtc_ret == -ENOENT) {
                                plane_target_display = -1;
                                break;
                            }
                            if (connector) {
                                drm_connector_free(&nv_dev->resource_mgr,
                                                   connector->id);
                            }
                            if (crtc) {
                                drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                            }
                            if (plane) {
                                drm_plane_free(&nv_dev->resource_mgr,
                                               plane->id);
                            }
                            return crtc_ret;
                        }
                        plane_target_display = (int)target_display;
                    }
                }
                break;

            case DRM_PROPERTY_ID_CRTC_X:
                if (plane) {
                    plane_x = (uint32_t)value;
                    plane_x_set = true;
                }
                break;
            case DRM_PROPERTY_ID_CRTC_Y:
                if (plane) {
                    plane_y = (uint32_t)value;
                    plane_y_set = true;
                }
                break;
            case DRM_PROPERTY_ID_CRTC_W:
                if (plane) {
                    plane_w = (uint32_t)value;
                    plane_w_set = true;
                }
                break;
            case DRM_PROPERTY_ID_CRTC_H:
                if (plane) {
                    plane_h = (uint32_t)value;
                    plane_h_set = true;
                }
                break;

            case DRM_PROPERTY_ID_SRC_X:
                if (plane) {
                    plane_src_x = (uint32_t)(value >> 16);
                    plane_src_x_set = true;
                }
                break;
            case DRM_PROPERTY_ID_SRC_Y:
                if (plane) {
                    plane_src_y = (uint32_t)(value >> 16);
                    plane_src_y_set = true;
                }
                break;
            case DRM_PROPERTY_ID_SRC_W:
                if (plane) {
                    plane_src_w = (uint32_t)(value >> 16);
                    plane_src_w_set = true;
                }
                break;
            case DRM_PROPERTY_ID_SRC_H:
                if (plane) {
                    plane_src_h = (uint32_t)(value >> 16);
                    plane_src_h_set = true;
                }
                break;

            case DRM_CRTC_ACTIVE_PROP_ID:
                if (crtc) {
                    states[display_idx].active = (value != 0);
                    if (value == 0) {
                        states[display_idx].fb_id = 0;
                    }
                    states[display_idx].touched = true;
                }
                break;

            case DRM_CRTC_MODE_ID_PROP_ID:
                if (crtc) {
                    if (value == 0) {
                        states[display_idx].mode_changed =
                            states[display_idx].mode_valid;
                        states[display_idx].mode_valid = false;
                        memset(&states[display_idx].mode, 0,
                               sizeof(states[display_idx].mode));
                    } else {
                        struct drm_mode_modeinfo requested_mode;
                        memset(&requested_mode, 0, sizeof(requested_mode));

                        int blob_ret = drm_property_get_modeinfo_from_blob(
                            drm_dev, (uint32_t)value, &requested_mode);
                        if (blob_ret != 0 || requested_mode.hdisplay == 0 ||
                            requested_mode.vdisplay == 0) {
                            if (connector) {
                                drm_connector_free(&nv_dev->resource_mgr,
                                                   connector->id);
                            }
                            if (crtc) {
                                drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                            }
                            if (plane) {
                                drm_plane_free(&nv_dev->resource_mgr,
                                               plane->id);
                            }
                            return blob_ret != 0 ? blob_ret : -EINVAL;
                        }

                        bool mode_was_valid = states[display_idx].mode_valid;
                        bool mode_unchanged =
                            mode_was_valid &&
                            memcmp(&states[display_idx].mode, &requested_mode,
                                   sizeof(requested_mode)) == 0;

                        states[display_idx].mode = requested_mode;
                        states[display_idx].mode_valid = true;
                        states[display_idx].mode_changed = !mode_unchanged;
                    }
                    states[display_idx].touched = true;
                }
                break;

            case DRM_CONNECTOR_DPMS_PROP_ID:
                if (value > DRM_MODE_DPMS_OFF) {
                    if (connector) {
                        drm_connector_free(&nv_dev->resource_mgr,
                                           connector->id);
                    }
                    if (crtc) {
                        drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
                    }
                    if (plane) {
                        drm_plane_free(&nv_dev->resource_mgr, plane->id);
                    }
                    return -EINVAL;
                }
                if (connector && value != DRM_MODE_DPMS_ON) {
                    states[display_idx].active = false;
                    states[display_idx].fb_id = 0;
                    states[display_idx].touched = true;
                }
                break;

            case DRM_CONNECTOR_CRTC_ID_PROP_ID:
                if (connector) {
                    if (value == 0) {
                        states[display_idx].connector_crtc_id = 0;
                        states[display_idx].active = false;
                        states[display_idx].fb_id = 0;
                    } else {
                        states[display_idx].connector_crtc_id = (uint32_t)value;
                    }
                    states[display_idx].touched = true;
                }
                break;

            default:
                break;
            }
        }

        if (plane) {
            if (plane_target_display >= 0 &&
                (uint32_t)plane_target_display < nv_dev->num_displays) {
                uint32_t dst = (uint32_t)plane_target_display;
                states[dst].fb_id = plane_fb_id;
                states[dst].active = plane_fb_id != 0;
                if (plane_x_set) {
                    states[dst].x = plane_x;
                }
                if (plane_y_set) {
                    states[dst].y = plane_y;
                }
                if (plane_w_set) {
                    states[dst].w = plane_w;
                }
                if (plane_h_set) {
                    states[dst].h = plane_h;
                }
                if (plane_src_x_set) {
                    states[dst].src_x = plane_src_x;
                }
                if (plane_src_y_set) {
                    states[dst].src_y = plane_src_y;
                }
                if (plane_src_w_set) {
                    states[dst].src_w = plane_src_w;
                }
                if (plane_src_h_set) {
                    states[dst].src_h = plane_src_h;
                }
                states[dst].touched = true;

                if (dst != display_idx) {
                    states[display_idx].fb_id = 0;
                    states[display_idx].active = false;
                    states[display_idx].touched = true;
                }
            } else {
                states[display_idx].fb_id = 0;
                states[display_idx].active = false;
                states[display_idx].touched = true;
            }
        }

        if (plane) {
            drm_plane_free(&nv_dev->resource_mgr, plane->id);
        }
        if (crtc) {
            drm_crtc_free(&nv_dev->resource_mgr, crtc->id);
        }
        if (connector) {
            drm_connector_free(&nv_dev->resource_mgr, connector->id);
        }
    }

    if (test_only) {
        for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
            if (!states[i].touched) {
                continue;
            }

            uint32_t crtc_idx = 0;
            if (nvidia_crtc_index_from_display(nv_dev, i, &crtc_idx) != 0 ||
                crtc_idx >= nv_dev->num_crtcs || !nv_dev->crtcs[crtc_idx]) {
                continue;
            }

            if (!states[i].connector_crtc_id) {
                states[i].active = false;
                states[i].fb_id = 0;
            }

            if (!states[i].active || !states[i].fb_id) {
                int ret = nvidia_apply_modeset(
                    nv_dev, i, NULL,
                    states[i].mode_valid ? &states[i].mode : NULL,
                    states[i].mode_changed, false, false, 0, states[i].x,
                    states[i].y, states[i].w, states[i].h, states[i].src_x,
                    states[i].src_y, states[i].src_w, states[i].src_h);
                if (ret != 0) {
                    return ret;
                }
                continue;
            }

            drm_framebuffer_t *drm_fb =
                drm_framebuffer_get(&nv_dev->resource_mgr, states[i].fb_id);
            if (!drm_fb) {
                return -ENOENT;
            }

            nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, drm_fb->handle);
            if (!nfb) {
                drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
                return -EINVAL;
            }

            drm_crtc_t *target_crtc = nv_dev->crtcs[crtc_idx];
            const struct drm_mode_modeinfo *mode =
                states[i].mode_valid
                    ? &states[i].mode
                    : (target_crtc->mode_valid ? &target_crtc->mode : NULL);
            if (!mode && nv_dev->connectors[i]) {
                const struct drm_mode_modeinfo *preferred_mode =
                    nvidia_preferred_connector_mode(nv_dev->connectors[i]);
                if (preferred_mode) {
                    states[i].mode = *preferred_mode;
                    states[i].mode_valid = true;
                    mode = &states[i].mode;
                }
            }

            uint32_t width = states[i].w
                                 ? states[i].w
                                 : (mode ? mode->hdisplay : drm_fb->width);
            uint32_t height = states[i].h
                                  ? states[i].h
                                  : (mode ? mode->vdisplay : drm_fb->height);
            uint32_t src_width = states[i].src_w ? states[i].src_w : width;
            uint32_t src_height = states[i].src_h ? states[i].src_h : height;

            int ret = nvidia_apply_modeset(
                nv_dev, i, nfb, mode, states[i].mode_changed, false, false, 0,
                states[i].x, states[i].y, width, height, states[i].src_x,
                states[i].src_y, src_width, src_height);
            drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
            if (ret != 0) {
                return ret;
            }
        }

        return 0;
    }

    bool request_flip_event = !!(atomic->flags & DRM_MODE_PAGE_FLIP_EVENT);
    bool mode_changed_any = false;
    int event_display_idx = -1;
    if (request_flip_event) {
        for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
            if (states[i].touched && states[i].mode_changed) {
                mode_changed_any = true;
                break;
            }
        }

        if (!mode_changed_any) {
            for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
                if (states[i].touched && states[i].active && states[i].fb_id &&
                    states[i].connector_crtc_id) {
                    event_display_idx = (int)i;
                    break;
                }
            }
            if (event_display_idx >= 0) {
                uint32_t head = nv_dev->display_heads[event_display_idx];
                if (head >= NVKMS_KAPI_MAX_HEADS) {
                    return -EINVAL;
                }
                if (nv_dev->pending_flip_event[head]) {
                    return -EBUSY;
                }
            }
        }
    }

    uint32_t apply_count = 0;
    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (!states[i].touched) {
            continue;
        }
        uint32_t crtc_idx = 0;
        if (nvidia_crtc_index_from_display(nv_dev, i, &crtc_idx) != 0 ||
            crtc_idx >= nv_dev->num_crtcs || !nv_dev->crtcs[crtc_idx]) {
            continue;
        }
        apply_count++;
    }

    bool applied_any = false;
    bool flip_event_armed = false;
    uint32_t applied_idx = 0;
    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (!states[i].touched) {
            continue;
        }

        uint32_t crtc_idx = 0;
        if (nvidia_crtc_index_from_display(nv_dev, i, &crtc_idx) != 0 ||
            crtc_idx >= nv_dev->num_crtcs) {
            continue;
        }

        drm_crtc_t *target_crtc = nv_dev->crtcs[crtc_idx];
        if (!target_crtc) {
            continue;
        }

        bool do_commit = (apply_count == 0) || (applied_idx + 1 == apply_count);

        if (!states[i].connector_crtc_id) {
            states[i].active = false;
            states[i].fb_id = 0;
        }

        int ret = 0;
        if (!states[i].active || !states[i].fb_id) {
            ret = nvidia_apply_modeset(
                nv_dev, i, NULL, states[i].mode_valid ? &states[i].mode : NULL,
                states[i].mode_changed, false, do_commit, 0, states[i].x,
                states[i].y, states[i].w, states[i].h, states[i].src_x,
                states[i].src_y, states[i].src_w, states[i].src_h);
            if (ret != 0) {
                return ret;
            }

            target_crtc->fb_id = 0;
            target_crtc->mode_valid = 0;
            if (nv_dev->planes[crtc_idx]) {
                nv_dev->planes[crtc_idx]->fb_id = 0;
            }
        } else {
            drm_framebuffer_t *drm_fb =
                drm_framebuffer_get(&nv_dev->resource_mgr, states[i].fb_id);
            if (!drm_fb) {
                states[i].active = false;
                states[i].fb_id = 0;
                continue;
            }

            nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, drm_fb->handle);
            if (!nfb) {
                drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
                states[i].active = false;
                states[i].fb_id = 0;
                continue;
            }

            const struct drm_mode_modeinfo *mode =
                states[i].mode_valid
                    ? &states[i].mode
                    : (target_crtc->mode_valid ? &target_crtc->mode : NULL);
            if (!mode && nv_dev->connectors[i]) {
                const struct drm_mode_modeinfo *preferred_mode =
                    nvidia_preferred_connector_mode(nv_dev->connectors[i]);
                if (preferred_mode) {
                    states[i].mode = *preferred_mode;
                    states[i].mode_valid = true;
                    mode = &states[i].mode;
                }
            }
            uint32_t width = states[i].w
                                 ? states[i].w
                                 : (mode ? mode->hdisplay : drm_fb->width);
            uint32_t height = states[i].h
                                  ? states[i].h
                                  : (mode ? mode->vdisplay : drm_fb->height);
            uint32_t src_width = states[i].src_w ? states[i].src_w : width;
            uint32_t src_height = states[i].src_h ? states[i].src_h : height;
            bool send_flip_event = request_flip_event && !mode_changed_any &&
                                   do_commit && ((int)i == event_display_idx);

            ret = nvidia_apply_modeset(
                nv_dev, i, nfb, mode, states[i].mode_changed, send_flip_event,
                do_commit, send_flip_event ? atomic->user_data : 0, states[i].x,
                states[i].y, width, height, states[i].src_x, states[i].src_y,
                src_width, src_height);
            drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
            if (ret != 0) {
                return ret;
            }
            if (send_flip_event) {
                flip_event_armed = true;
            }

            target_crtc->fb_id = states[i].fb_id;
            target_crtc->x = states[i].x;
            target_crtc->y = states[i].y;
            target_crtc->w = width;
            target_crtc->h = height;
            if (states[i].mode_valid) {
                target_crtc->mode = states[i].mode;
                target_crtc->mode_valid = 1;
            }
            if (nv_dev->planes[crtc_idx]) {
                nv_dev->planes[crtc_idx]->fb_id = states[i].fb_id;
                nv_dev->planes[crtc_idx]->crtc_id = target_crtc->id;
            }
        }

        if (nv_dev->connectors[i]) {
            nv_dev->connectors[i]->crtc_id = states[i].connector_crtc_id;
        }
        applied_any = true;
        applied_idx++;
    }

    if (applied_any && request_flip_event &&
        (mode_changed_any || !flip_event_armed)) {
        drm_post_event(drm_dev, DRM_EVENT_FLIP_COMPLETE, atomic->user_data);
    }

    return 0;
}

int nvidia_map_dumb(drm_device_t *drm_dev, struct drm_mode_map_dumb *args) {
    if (!drm_dev || !args) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    nvidia_fb_t *fb = nvidia_fb_by_handle(nv_dev, args->handle);
    if (!fb) {
        return -EINVAL;
    }

    args->offset = fb->map_offset;
    return 0;
}

int nvidia_set_crtc(drm_device_t *drm_dev, struct drm_mode_crtc *crtc) {
    if (!drm_dev || !crtc) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    uint32_t display_idx = 0;
    int ret =
        nvidia_display_index_from_crtc(nv_dev, crtc->crtc_id, &display_idx);
    if (ret != 0) {
        return ret;
    }

    uint32_t crtc_idx = 0;
    ret = nvidia_crtc_index_from_display(nv_dev, display_idx, &crtc_idx);
    if (ret != 0) {
        return ret;
    }

    drm_crtc_t *target_crtc = nv_dev->crtcs[crtc_idx];
    if (!target_crtc) {
        return -ENOENT;
    }

    if (crtc->fb_id != 0 && !crtc->mode_valid) {
        return -EINVAL;
    }

    if (crtc->fb_id == 0) {
        ret =
            nvidia_apply_modeset(nv_dev, display_idx, NULL, NULL, false, false,
                                 true, 0, crtc->x, crtc->y, 0, 0, 0, 0, 0, 0);
        if (ret == 0) {
            target_crtc->fb_id = 0;
            target_crtc->mode_valid = 0;
            if (nv_dev->planes[crtc_idx]) {
                nv_dev->planes[crtc_idx]->fb_id = 0;
            }
        }
        return ret;
    }

    drm_framebuffer_t *drm_fb =
        drm_framebuffer_get(&nv_dev->resource_mgr, crtc->fb_id);
    if (!drm_fb) {
        return -ENOENT;
    }

    nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, drm_fb->handle);
    if (!nfb) {
        drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
        return -EINVAL;
    }

    const struct drm_mode_modeinfo *mode = &crtc->mode;

    uint32_t width = crtc->mode.hdisplay ? crtc->mode.hdisplay : drm_fb->width;
    uint32_t height =
        crtc->mode.vdisplay ? crtc->mode.vdisplay : drm_fb->height;

    ret = nvidia_apply_modeset(nv_dev, display_idx, nfb, mode, crtc->mode_valid,
                               false, true, 0, crtc->x, crtc->y, width, height,
                               0, 0, width, height);
    if (ret == 0) {
        target_crtc->fb_id = crtc->fb_id;
        target_crtc->x = crtc->x;
        target_crtc->y = crtc->y;
        target_crtc->w = width;
        target_crtc->h = height;
        if (crtc->mode_valid) {
            target_crtc->mode = crtc->mode;
            target_crtc->mode_valid = 1;
        }
        if (nv_dev->planes[crtc_idx]) {
            nv_dev->planes[crtc_idx]->fb_id = crtc->fb_id;
        }
    }

    drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
    return ret;
}

int nvidia_page_flip(struct drm_device *dev,
                     struct drm_mode_crtc_page_flip *flip) {
    if (!dev || !flip) {
        return -EINVAL;
    }

    if (flip->flags & ~DRM_MODE_PAGE_FLIP_FLAGS) {
        return -EINVAL;
    }
    if (flip->flags & DRM_MODE_PAGE_FLIP_TARGET) {
        return -EINVAL;
    }
    if (flip->reserved != 0) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = dev->data;
    if (!nv_dev) {
        return -ENODEV;
    }

    uint32_t display_idx = 0;
    int ret =
        nvidia_display_index_from_crtc(nv_dev, flip->crtc_id, &display_idx);
    if (ret != 0) {
        return ret;
    }

    uint32_t crtc_idx = 0;
    ret = nvidia_crtc_index_from_display(nv_dev, display_idx, &crtc_idx);
    if (ret != 0) {
        return ret;
    }

    drm_crtc_t *crtc = nv_dev->crtcs[crtc_idx];
    if (!crtc) {
        return -ENOENT;
    }

    uint32_t head = nv_dev->display_heads[display_idx];
    if (head >= NVKMS_KAPI_MAX_HEADS) {
        return -EINVAL;
    }
    if ((flip->flags & DRM_MODE_PAGE_FLIP_EVENT) &&
        nv_dev->pending_flip_event[head]) {
        return -EBUSY;
    }

    drm_framebuffer_t *drm_fb =
        drm_framebuffer_get(&nv_dev->resource_mgr, flip->fb_id);
    if (!drm_fb) {
        return -ENOENT;
    }

    nvidia_fb_t *nfb = nvidia_fb_by_handle(nv_dev, drm_fb->handle);
    if (!nfb) {
        drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
        return -EINVAL;
    }

    const struct drm_mode_modeinfo *mode =
        crtc->mode_valid ? &crtc->mode : NULL;
    uint32_t dst_width = crtc->w ? crtc->w : drm_fb->width;
    uint32_t dst_height = crtc->h ? crtc->h : drm_fb->height;
    ret = nvidia_apply_modeset(nv_dev, display_idx, nfb, mode, false,
                               !!(flip->flags & DRM_MODE_PAGE_FLIP_EVENT), true,
                               flip->user_data, crtc->x, crtc->y, dst_width,
                               dst_height, 0, 0, dst_width, dst_height);

    if (ret == 0) {
        crtc->fb_id = flip->fb_id;
        if (nv_dev->planes[crtc_idx]) {
            nv_dev->planes[crtc_idx]->fb_id = flip->fb_id;
        }
    }

    drm_framebuffer_free(&nv_dev->resource_mgr, drm_fb->id);
    return ret;
}

int nvidia_set_cursor(drm_device_t *drm_dev, struct drm_mode_cursor *cursor) {
    (void)drm_dev;
    (void)cursor;
    return -ENOTSUP;
}

int nvidia_gamma_set(drm_device_t *drm_dev, struct drm_mode_crtc_lut *gamma) {
    (void)drm_dev;
    (void)gamma;
    return -ENOTSUP;
}

int nvidia_get_connectors(drm_device_t *drm_dev, drm_connector_t **connectors,
                          uint32_t *count) {
    if (!drm_dev || !connectors || !count) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    *count = 0;
    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (nv_dev->connectors[i]) {
            connectors[(*count)++] = nv_dev->connectors[i];
        }
    }

    return 0;
}

int nvidia_get_crtcs(drm_device_t *drm_dev, drm_crtc_t **crtcs,
                     uint32_t *count) {
    if (!drm_dev || !crtcs || !count) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    *count = 0;
    for (uint32_t i = 0; i < nv_dev->num_crtcs; i++) {
        if (nv_dev->crtcs[i]) {
            crtcs[(*count)++] = nv_dev->crtcs[i];
        }
    }

    return 0;
}

int nvidia_get_encoders(drm_device_t *drm_dev, drm_encoder_t **encoders,
                        uint32_t *count) {
    if (!drm_dev || !encoders || !count) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    *count = 0;
    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        if (nv_dev->encoders[i]) {
            encoders[(*count)++] = nv_dev->encoders[i];
        }
    }

    return 0;
}

int nvidia_get_planes(drm_device_t *drm_dev, drm_plane_t **planes,
                      uint32_t *count) {
    if (!drm_dev || !planes || !count) {
        return -EINVAL;
    }

    nvidia_device_t *nv_dev = drm_dev->data;
    *count = 0;
    for (uint32_t i = 0; i < nv_dev->num_crtcs; i++) {
        if (nv_dev->planes[i]) {
            planes[(*count)++] = nv_dev->planes[i];
        }
    }

    return *count ? 0 : -ENODEV;
}

// DRM device operations structure
drm_device_op_t nvidia_drm_device_op = {
    .get_display_info = nvidia_get_display_info,
    .get_fb = nvidia_get_fb,
    .create_dumb = nvidia_create_dumb,
    .destroy_dumb = nvidia_destroy_dumb,
    .dirty_fb = nvidia_dirty_fb,
    .add_fb = nvidia_add_fb,
    .add_fb2 = nvidia_add_fb2,
    .set_plane = nvidia_set_plane,
    .atomic_commit = nvidia_atomic_commit,
    .map_dumb = nvidia_map_dumb,
    .set_crtc = nvidia_set_crtc,
    .page_flip = nvidia_page_flip,
    .set_cursor = nvidia_set_cursor,
    .gamma_set = nvidia_gamma_set,
    .get_connectors = nvidia_get_connectors,
    .get_crtcs = nvidia_get_crtcs,
    .get_encoders = nvidia_get_encoders,
    .get_planes = nvidia_get_planes,
};

void nvidia_eventCallback(const struct NvKmsKapiEvent *event) {
    if (!event || !event->privateData) {
        return;
    }

    nvidia_device_t *nv_dev = (nvidia_device_t *)event->privateData;
    switch (event->type) {
    case NVKMS_EVENT_TYPE_DPY_CHANGED:
    case NVKMS_EVENT_TYPE_DYNAMIC_DPY_CONNECTED:
        for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
            nvidia_update_display_connector_state(nv_dev, i);
        }
        break;
    case NVKMS_EVENT_TYPE_FLIP_OCCURRED: {
        uint32_t head = event->u.flipOccurred.head;
        if (nv_dev->drm_dev) {
            nv_dev->drm_dev->vblank_counter++;
            if (head < NVKMS_KAPI_MAX_HEADS &&
                nv_dev->pending_flip_event[head]) {
                drm_post_event(nv_dev->drm_dev, DRM_EVENT_FLIP_COMPLETE,
                               nv_dev->pending_flip_user_data[head]);
                nv_dev->pending_flip_event[head] = false;
                nv_dev->pending_flip_user_data[head] = 0;
            }
        }
        break;
    }
    default:
        printk("nvidia_open: Unhandled event type %d\n", event->type);
    }
    return;
}

int nvidia_probe(pci_device_t *dev, uint32_t vendor_device_id) {
    (void)vendor_device_id;

    if (!dev) {
        return -EINVAL;
    }

    if (nvidia_gpu_count >= MAX_NVIDIA_GPU_NUM) {
        printk("nvidia_open: too many NVIDIA GPUs (max=%u)\n",
               (uint32_t)MAX_NVIDIA_GPU_NUM);
        return -ENOSPC;
    }

    uint16_t vendor = dev->vendor_id;
    uint16_t device = dev->device_id;
    uint16_t subsystem_vendor = dev->subsystem_vendor_id;
    uint16_t subsystem_device = dev->subsystem_device_id;

    if (!rm_wait_for_bar_firewall(NULL, dev->segment, dev->bus, dev->slot,
                                  dev->func, device)) {
        printk("NVRM: failed to wait for bar firewall to lower!!!\n");
        return -1;
    }

    bool supported = rm_is_supported_pci_device(
        (dev->class_code >> 16) & 0xFF, (dev->class_code >> 8) & 0xFF, vendor,
        device, subsystem_vendor, subsystem_device, NV_TRUE);

    if (!supported) {
        printk("NVIDIA device not supported!!!\n");
        return -1;
    }

    nvidia_device_t *nv_dev = calloc(1, sizeof(nvidia_device_t));
    if (!nv_dev) {
        return -ENOMEM;
    }
    bool registered_gpu = false;
    bool private_state_initialized = false;
    bool gpu_notified = false;
    bool kms_device_allocated = false;
    bool kms_ownership_grabbed = false;

    nv_dev->pci_dev = dev;
    nv_dev->timerLock.lock = 0;

    nv_dev->nv_.pci_info.domain = dev->segment;
    nv_dev->nv_.pci_info.bus = dev->bus;
    nv_dev->nv_.pci_info.slot = dev->slot;
    nv_dev->nv_.pci_info.function = dev->func;
    nv_dev->nv_.pci_info.vendor_id = dev->vendor_id;
    nv_dev->nv_.pci_info.device_id = dev->device_id;
    nv_dev->nv_.subsystem_vendor = dev->subsystem_vendor_id;
    nv_dev->nv_.subsystem_id = dev->subsystem_device_id;
    nv_dev->nv_.os_state = nv_dev;
    nv_dev->nv_.handle = nv_dev->pci_dev;
    nv_dev->nv_.cpu_numa_node_id = -1;
    nv_dev->nv_.interrupt_line = dev->irq_line;

    if (dev->op) {
        uint16_t command = dev->op->read16(dev->bus, dev->slot, dev->func,
                                           dev->segment, PCI_CONF_COMMAND);
        command |= 0x6;
        dev->op->write16(dev->bus, dev->slot, dev->func, dev->segment,
                         PCI_CONF_COMMAND, command);
    }

    size_t nvBarIndex = 0;

    for (size_t i = 0; i < 6; i++) {
        if (dev->bars[i].address && dev->bars[i].mmio) {
            if (nvBarIndex >= NV_GPU_NUM_BARS) {
                continue;
            }
            nv_dev->nv_.bars[nvBarIndex].cpu_address =
                dev->bars[i].address & ~(DEFAULT_PAGE_SIZE - 1);
            nv_dev->nv_.bars[nvBarIndex].size = dev->bars[i].size;
            nv_dev->nv_.bars[nvBarIndex].offset =
                dev->bars[i].address & (DEFAULT_PAGE_SIZE - 1);
            nv_dev->nv_.bars[nvBarIndex].map = NULL;
            nv_dev->nv_.bars[nvBarIndex].map_u = NULL;
            nvBarIndex++;
        }
    }

    nv_dev->nv_.regs = &nv_dev->nv_.bars[NV_GPU_BAR_INDEX_REGS];
    nv_dev->nv_.fb = &nv_dev->nv_.bars[NV_GPU_BAR_INDEX_FB];
    if (nv_dev->nv_.regs->cpu_address == 0 || nv_dev->nv_.regs->size == 0 ||
        nv_dev->nv_.fb->cpu_address == 0 || nv_dev->nv_.fb->size == 0) {
        printk("nvidia_open: invalid BAR layout (regs/fb missing)\n");
        free(nv_dev);
        return -1;
    }

    nvidia_gpus[nvidia_gpu_count] = nv_dev;
    nvidia_gpu_count++;
    registered_gpu = true;

    NV_STATUS status = rm_is_supported_device(NULL, &nv_dev->nv_);
    if (status != NV_OK) {
        printk("Failed detect support device!!!\n");
        goto fail;
    }

    bool success = rm_init_private_state(NULL, &nv_dev->nv_);
    if (!success) {
        printk("Failed init private state!!!\n");
        goto fail;
    }
    private_state_initialized = true;

    rm_set_rm_firmware_requested(NULL, &nv_dev->nv_);
    rm_enable_dynamic_power_management(NULL, &nv_dev->nv_);

    rm_notify_gpu_addition(NULL, &nv_dev->nv_);
    gpu_notified = true;

    rm_unref_dynamic_power(NULL, &nv_dev->nv_, NV_DYNAMIC_PM_FINE);

    nvKmsLock.lock = 0;

    static struct NvKmsKapiFunctionsTable nvKmsFuncsTable = {
        .versionString = NV_VERSION_STRING,
    };

    nvKms = &nvKmsFuncsTable;

    if (!nvKmsKapiGetFunctionsTableInternal(&nvKmsFuncsTable)) {
        goto fail;
    }
    nvKmsModuleLoad();

    struct NvKmsKapiAllocateDeviceParams params = {
        .gpuId = nv_dev->nv_.gpu_id,
        .privateData = nv_dev,
        .eventCallback = nvidia_eventCallback,
    };

    nv_dev->kmsdev = nvKms->allocateDevice(&params);
    if (!nv_dev->kmsdev) {
        printk("Failed to allocate kms device!!!\n");
        goto fail;
    }
    kms_device_allocated = true;

    if (!nvKms->grabOwnership(nv_dev->kmsdev)) {
        goto fail;
    }
    kms_ownership_grabbed = true;

    nvKms->framebufferConsoleDisabled(nv_dev->kmsdev);

    struct NvKmsKapiDeviceResourcesInfo resInfo;
    if (!nvKms->getDeviceResourcesInfo(nv_dev->kmsdev, &resInfo)) {
        goto fail;
    }
    nv_dev->pitch_alignment = resInfo.caps.pitchAlignment;
    nv_dev->has_video_memory = !!resInfo.caps.hasVideoMemory;

    drm_resource_manager_init(&nv_dev->resource_mgr);
    nv_dev->num_crtcs = 0;
    for (uint32_t i = 0; i < NVKMS_KAPI_MAX_HEADS; i++) {
        nv_dev->head_to_crtc[i] = -1;
    }

    NvU32 nDisplays = 0;
    success = nvKms->getDisplays(nv_dev->kmsdev, &nDisplays, NULL);
    if (!success) {
        goto fail;
    }

    if (nDisplays > 16) {
        nDisplays = 16;
    }

    NvKmsKapiDisplay hDisplays[16] = {0};
    success = nvKms->getDisplays(nv_dev->kmsdev, &nDisplays, hDisplays);
    if (!success) {
        goto fail;
    }

    uint32_t head_order[NVKMS_KAPI_MAX_HEADS] = {0};
    uint32_t head_order_count = 0;
    bool head_ordered[NVKMS_KAPI_MAX_HEADS] = {false};

    for (uint32_t i = 0; i < nDisplays; i++) {
        struct NvKmsKapiStaticDisplayInfo display_info;
        memset(&display_info, 0, sizeof(display_info));
        if (!nvKms->getStaticDisplayInfo(nv_dev->kmsdev, hDisplays[i],
                                         &display_info)) {
            continue;
        }

        for (uint32_t bit = 0;
             bit < resInfo.numHeads && bit < NVKMS_KAPI_MAX_HEADS; bit++) {
            if (!(display_info.headMask & (1U << bit))) {
                continue;
            }
            if (resInfo.numLayers[bit] <= NVKMS_KAPI_LAYER_PRIMARY_IDX ||
                head_ordered[bit]) {
                continue;
            }

            head_order[head_order_count++] = bit;
            head_ordered[bit] = true;
        }
    }

    for (uint32_t bit = 0; bit < resInfo.numHeads && bit < NVKMS_KAPI_MAX_HEADS;
         bit++) {
        if (resInfo.numLayers[bit] <= NVKMS_KAPI_LAYER_PRIMARY_IDX ||
            head_ordered[bit]) {
            continue;
        }
        head_order[head_order_count++] = bit;
        head_ordered[bit] = true;
    }

    for (uint32_t i = 0;
         i < head_order_count && nv_dev->num_crtcs < DRM_MAX_CRTCS_PER_DEVICE &&
         nv_dev->num_crtcs < DRM_MAX_PLANES_PER_DEVICE;
         i++) {
        uint32_t head = head_order[i];
        uint32_t crtc_idx = nv_dev->num_crtcs;
        drm_crtc_t *crtc = drm_crtc_alloc(&nv_dev->resource_mgr, nv_dev);
        if (!crtc) {
            continue;
        }

        crtc->x = 0;
        crtc->y = 0;
        crtc->w = 0;
        crtc->h = 0;
        crtc->mode_valid = 0;
        nv_dev->crtcs[crtc_idx] = crtc;
        nv_dev->head_to_crtc[head] = (int8_t)crtc_idx;

        drm_plane_t *plane = drm_plane_alloc(&nv_dev->resource_mgr, nv_dev);
        if (plane) {
            plane->crtc_id = crtc->id;
            plane->possible_crtcs = 1U << crtc_idx;

            uint32_t formats[8] = {0};
            uint32_t format_count = nvidia_get_drm_formats_from_mask(
                resInfo.supportedSurfaceMemoryFormats
                    [NVKMS_KAPI_LAYER_PRIMARY_IDX],
                formats, 8);
            if (!format_count) {
                formats[0] = DRM_FORMAT_XRGB8888;
                formats[1] = DRM_FORMAT_ARGB8888;
                formats[2] = DRM_FORMAT_XBGR8888;
                format_count = 3;
            }

            plane->count_format_types = format_count;
            plane->format_types = malloc(sizeof(uint32_t) * format_count);
            if (plane->format_types) {
                memcpy(plane->format_types, formats,
                       sizeof(uint32_t) * format_count);
            } else {
                plane->count_format_types = 0;
            }
            plane->plane_type = DRM_PLANE_TYPE_PRIMARY;
        }
        nv_dev->planes[crtc_idx] = plane;
        nv_dev->num_crtcs++;
    }

    nv_dev->num_displays = 0;
    bool head_assigned[NVKMS_KAPI_MAX_HEADS] = {false};
    for (uint32_t i = 0; i < nDisplays; i++) {
        if (nv_dev->num_displays >= DRM_MAX_CONNECTORS_PER_DEVICE ||
            nv_dev->num_displays >= DRM_MAX_ENCODERS_PER_DEVICE) {
            break;
        }

        struct NvKmsKapiStaticDisplayInfo display_info;
        struct NvKmsKapiConnectorInfo connector_info;
        memset(&display_info, 0, sizeof(display_info));
        memset(&connector_info, 0, sizeof(connector_info));

        if (!nvKms->getStaticDisplayInfo(nv_dev->kmsdev, hDisplays[i],
                                         &display_info)) {
            continue;
        }
        if (!nvKms->getConnectorInfo(nv_dev->kmsdev,
                                     display_info.connectorHandle,
                                     &connector_info)) {
            continue;
        }

        int selected_head = -1;
        for (uint32_t bit = 0; bit < NVKMS_KAPI_MAX_HEADS; bit++) {
            if (!(display_info.headMask & (1U << bit))) {
                continue;
            }
            if (nv_dev->head_to_crtc[bit] < 0 || head_assigned[bit]) {
                continue;
            }
            selected_head = bit;
            break;
        }

        if (selected_head < 0) {
            for (uint32_t bit = 0; bit < NVKMS_KAPI_MAX_HEADS; bit++) {
                if ((display_info.headMask & (1U << bit)) &&
                    nv_dev->head_to_crtc[bit] >= 0) {
                    selected_head = bit;
                    break;
                }
            }
        }

        if (selected_head < 0) {
            continue;
        }

        head_assigned[selected_head] = true;

        uint32_t crtc_idx = (uint32_t)nv_dev->head_to_crtc[selected_head];
        if (crtc_idx >= nv_dev->num_crtcs || !nv_dev->crtcs[crtc_idx]) {
            continue;
        }

        uint32_t display_idx = nv_dev->num_displays;
        nv_dev->displays[display_idx] = hDisplays[i];
        nv_dev->display_connectors[display_idx] = display_info.connectorHandle;
        nv_dev->display_heads[display_idx] = (uint32_t)selected_head;
        printk("nvidia_open: display[%u]=0x%08x head=%u headMask=0x%x\n",
               display_idx, hDisplays[i], (uint32_t)selected_head,
               display_info.headMask);

        uint32_t connector_type = nvidia_connector_type_to_drm(
            connector_info.type, display_info.internal);
        nv_dev->connectors[display_idx] =
            drm_connector_alloc(&nv_dev->resource_mgr, connector_type, nv_dev);
        if (!nv_dev->connectors[display_idx]) {
            continue;
        }

        nv_dev->encoders[display_idx] = drm_encoder_alloc(
            &nv_dev->resource_mgr,
            nvidia_signal_format_to_drm(connector_info.signalFormat), nv_dev);
        if (!nv_dev->encoders[display_idx]) {
            drm_connector_free(&nv_dev->resource_mgr,
                               nv_dev->connectors[display_idx]->id);
            nv_dev->connectors[display_idx] = NULL;
            continue;
        }

        uint32_t possible_crtcs = 0;
        for (uint32_t bit = 0; bit < NVKMS_KAPI_MAX_HEADS; bit++) {
            if (!(display_info.headMask & (1U << bit))) {
                continue;
            }

            if (nv_dev->head_to_crtc[bit] >= 0) {
                possible_crtcs |= (1U << nv_dev->head_to_crtc[bit]);
            }
        }
        if (!possible_crtcs) {
            possible_crtcs = 1U << crtc_idx;
        }

        nv_dev->encoders[display_idx]->possible_crtcs = possible_crtcs;
        nv_dev->encoders[display_idx]->crtc_id = nv_dev->crtcs[crtc_idx]->id;

        nv_dev->connectors[display_idx]->encoder_id =
            nv_dev->encoders[display_idx]->id;
        nv_dev->connectors[display_idx]->crtc_id = nv_dev->crtcs[crtc_idx]->id;

        nvidia_update_display_connector_state(nv_dev, display_idx);

        if (nv_dev->connectors[display_idx]->count_modes &&
            nv_dev->connectors[display_idx]->modes &&
            !nv_dev->crtcs[crtc_idx]->mode_valid) {
            const struct drm_mode_modeinfo *preferred_mode =
                nvidia_preferred_connector_mode(
                    nv_dev->connectors[display_idx]);
            if (preferred_mode) {
                nv_dev->crtcs[crtc_idx]->mode = *preferred_mode;
                nv_dev->crtcs[crtc_idx]->w = preferred_mode->hdisplay;
                nv_dev->crtcs[crtc_idx]->h = preferred_mode->vdisplay;
                nv_dev->crtcs[crtc_idx]->mode_valid = 1;
            }
        }

        if (nv_dev->planes[crtc_idx]) {
            nv_dev->planes[crtc_idx]->crtc_id = nv_dev->crtcs[crtc_idx]->id;
        }

        nv_dev->num_displays++;
    }

    nvidia_build_incompatible_display_map(nv_dev);
    for (uint32_t i = 0; i < nv_dev->num_displays; i++) {
        nvidia_update_display_connector_state(nv_dev, i);
    }

    success = nvKms->declareEventInterest(
        nv_dev->kmsdev, ((1U << NVKMS_EVENT_TYPE_DPY_CHANGED) |
                         (1U << NVKMS_EVENT_TYPE_DYNAMIC_DPY_CONNECTED) |
                         (1U << NVKMS_EVENT_TYPE_FLIP_OCCURRED)));

    if (!success) {
        goto fail;
    }

    printk("nvidia_open: heads=%u, crtcs=%u, displays=%u\n", resInfo.numHeads,
           nv_dev->num_crtcs, nv_dev->num_displays);

    nv_dev->drm_dev =
        drm_regist_pci_dev(nv_dev, &nvidia_drm_device_op, nv_dev->pci_dev);
    if (!nv_dev->drm_dev) {
        goto fail;
    }

    drm_device_set_driver_info(nv_dev->drm_dev, "nvidia_open", "20260226",
                               "NVIDIA Open Kernel DRM (NaOS)");

    printk("nvidia_open: drm primary node /dev/dri/card%u\n",
           nv_dev->drm_dev->primary_minor);
    if (nv_dev->drm_dev->render_node_registered) {
        printk("nvidia_open: drm render node /dev/dri/renderD%u\n",
               nv_dev->drm_dev->render_minor);
    }

    return 0;

fail:
    nv_dev->tasks_should_exit = true;
    while ((nv_dev->irq_handler_task &&
            nv_dev->irq_handler_task->state != TASK_DIED) ||
           (nv_dev->timer_task && nv_dev->timer_task->state != TASK_DIED)) {
        arch_pause();
    }

    if (kms_ownership_grabbed && nvKms && nvKms->releaseOwnership &&
        nv_dev->kmsdev) {
        nvKms->releaseOwnership(nv_dev->kmsdev);
    }
    if (kms_device_allocated && nvKms && nvKms->freeDevice && nv_dev->kmsdev) {
        nvKms->freeDevice(nv_dev->kmsdev);
    }
    if (gpu_notified) {
        rm_notify_gpu_removal(NULL, &nv_dev->nv_);
    }
    if (private_state_initialized) {
        rm_free_private_state(NULL, &nv_dev->nv_);
    }
    if (registered_gpu) {
        nvidia_unregister_gpu(nv_dev);
    }
    free(nv_dev);
    return -1;
}

void nvidia_remove(pci_device_t *dev) {}

void nvidia_shutdown(pci_device_t *dev) {}

static void nvidia_open_process_rm_interrupts(nvidia_device_t *dev) {
    if (!dev || dev->tasks_should_exit) {
        return;
    }

    __atomic_add_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);

    uint32_t rm_serviceable_fault_cnt = 0;
    rm_gpu_handle_mmu_faults(NULL, &dev->nv_, &rm_serviceable_fault_cnt);

    uint32_t need_to_run_bottom_half_gpu_lock_held = 0;
    rm_isr(NULL, &dev->nv_, &need_to_run_bottom_half_gpu_lock_held);

    if (need_to_run_bottom_half_gpu_lock_held) {
        rm_isr_bh(NULL, &dev->nv_);
    }

    __atomic_sub_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);
}

static void nvidia_open_process_rm_bottom_half(nvidia_device_t *dev) {
    if (!dev || dev->tasks_should_exit) {
        return;
    }

    __atomic_add_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);

    uint32_t rm_serviceable_fault_cnt = 0;
    rm_gpu_handle_mmu_faults(NULL, &dev->nv_, &rm_serviceable_fault_cnt);
    rm_isr_bh(NULL, &dev->nv_);

    __atomic_sub_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);
}

static void nvidia_open_irq_handler(uint64_t irq_num, void *data,
                                    struct pt_regs *regs) {
    (void)regs;

    nvidia_device_t *dev = (nvidia_device_t *)data;
    if (!dev || dev->tasks_should_exit) {
        return;
    }

    __atomic_add_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);
    uint32_t need_to_run_bottom_half_gpu_lock_held = 0;
    rm_isr(NULL, &dev->nv_, &need_to_run_bottom_half_gpu_lock_held);
    __atomic_sub_fetch(&nvidia_open_irq_nesting, 1, __ATOMIC_ACQ_REL);

    if (need_to_run_bottom_half_gpu_lock_held) {
        __atomic_add_fetch(&dev->irq_work_pending, 1, __ATOMIC_RELEASE);
    }
}

static int nvidia_setup_msix(nvidia_device_t *dev) {
#if defined(__x86_64__)
    if (!dev || !dev->pci_dev) {
        return -EINVAL;
    }

    if (dev->msix_enabled) {
        return 0;
    }

    if (!rm_is_msix_allowed(NULL, &dev->nv_)) {
        return -ENOTSUP;
    }

    if (!dev->nv_.interrupt_line || dev->nv_.interrupt_line == 0xFF) {
        return -ENOTSUP;
    }

    int vector = 32 + dev->nv_.interrupt_line;
    if (vector < 0) {
        return vector;
    }

    memset(&dev->msi_desc, 0, sizeof(dev->msi_desc));
    dev->msi_desc.irq_num = (uint16_t)vector;
    dev->msi_desc.processor = (uint32_t)get_lapicid_by_cpuid(0);
    dev->msi_desc.edge_trigger = 1;
    dev->msi_desc.assert = 0;
    dev->msi_desc.pci_dev = dev->pci_dev;
    dev->msi_desc.msi_index = 0;
    dev->msi_desc.pci.msi_attribute.is_msix = 1;
    dev->msi_desc.pci.msi_attribute.can_mask = 1;
    dev->msi_desc.pci.msi_attribute.is_64 = 1;

    int ret = pci_enable_msi(&dev->msi_desc);
    if (ret < 0) {
        return ret;
    }

    irq_regist_irq((uint64_t)vector, nvidia_open_irq_handler, 0, dev,
                   get_apic_controller(), "nvidia_open_msix", IRQ_FLAGS_MSIX);

    dev->irq_vector = (uint32_t)vector;
    dev->msix_enabled = true;

    printk("nvidia_open: MSI-X enabled vector=%d cpu_lapic=%u edge=%u "
           "assert=%u\n",
           vector, dev->msi_desc.processor, dev->msi_desc.edge_trigger,
           dev->msi_desc.assert);

    return 0;
#else
    (void)dev;
    return -ENOTSUP;
#endif
}

void nvidia_open_irq_thread(uint64_t dev_ptr) {
    nvidia_device_t *dev = (nvidia_device_t *)dev_ptr;

    arch_enable_interrupt();

    while (!dev->shouldEnableIrq) {
        if (dev->tasks_should_exit) {
            task_exit(0);
        }

        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
    }

    while (1) {
        arch_enable_interrupt();

        if (dev->tasks_should_exit) {
            task_exit(0);
        }

        if (dev->msix_enabled) {
            NvU32 pending = __atomic_exchange_n(&dev->irq_work_pending, 0,
                                                __ATOMIC_ACQ_REL);
            if (!pending) {
                schedule(SCHED_FLAG_YIELD);
                continue;
            }
            for (NvU32 i = 0; i < pending; i++) {
                nvidia_open_process_rm_bottom_half(dev);
            }
        } else {
            nvidia_open_process_rm_interrupts(dev);
        }

        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
    }

    task_exit(0);
}

void nvidia_open_rc_timer(uint64_t dev_ptr) {
    nvidia_device_t *dev = (nvidia_device_t *)dev_ptr;

    bool continueWaiting = true;

    arch_enable_interrupt();

    while (1) {
        arch_enable_interrupt();

        if (dev->tasks_should_exit) {
            task_exit(0);
        }

        while (!dev->nv_.rc_timer_enabled || !continueWaiting) {
            if (dev->tasks_should_exit) {
                task_exit(0);
            }

            schedule(SCHED_FLAG_YIELD);

            if (dev->nv_.rc_timer_enabled) {
                continueWaiting = true;
            }
        }

        os_delay(1000);

        spin_lock(&dev->timerLock);
        bool still_enabled = dev->nv_.rc_timer_enabled;
        spin_unlock(&dev->timerLock);

        if (!still_enabled)
            goto next;

        NV_STATUS status = rm_run_rc_callback(NULL, &dev->nv_);
        if (status != NV_OK) {
            continueWaiting = false;
        }

    next:
        arch_enable_interrupt();

        schedule(SCHED_FLAG_YIELD);
    }
}

NvBool nvidia_open_do_open_gpu(nvidia_device_t *dev) {
    if (!dev) {
        return NV_FALSE;
    }

    if (dev->nv_.flags & NV_FLAG_OPEN)
        return NV_TRUE;

    if (!dev->adapterInitialized_) {
        rm_ref_dynamic_power(NULL, &dev->nv_, NV_DYNAMIC_PM_COARSE);

        dev->irq_handler_task =
            task_create("NVIDIA_OPEN_IRQ_HANDLER", nvidia_open_irq_thread,
                        (uint64_t)dev, KTHREAD_PRIORITY);

        int msix_ret = nvidia_setup_msix(dev);
        if (msix_ret != 0) {
            printk("nvidia_open: MSI-X unavailable (%d), fallback to polling "
                   "IRQ thread\n",
                   msix_ret);
        }
        dev->shouldEnableIrq = true;

        dev->timer_task = task_create("NVIDIA_OPEN_TIMER", nvidia_open_rc_timer,
                                      (uint64_t)dev, KTHREAD_PRIORITY);
        bool success = rm_init_adapter(NULL, &dev->nv_);
        if (!success) {
            rm_unref_dynamic_power(NULL, &dev->nv_, NV_DYNAMIC_PM_COARSE);
            return NV_FALSE;
        }

        dev->adapterInitialized_ = true;
    }

    dev->nv_.flags |= NV_FLAG_OPEN;

    rm_request_dnotifier_state(NULL, &dev->nv_);

    return NV_TRUE;
}

NvBool nvidia_open_open_gpu(NvU32 gpuId) {
    for (uint64_t i = 0; i < nvidia_gpu_count; i++) {
        if (!nvidia_gpus[i]) {
            continue;
        }
        if (nvidia_gpus[i]->nv_.gpu_id == gpuId) {
            return nvidia_open_do_open_gpu(nvidia_gpus[i]);
        }
    }

    return NV_FALSE;
}

pci_driver_t nvidia_pci_driver = {
    .name = "nvidia_open",
    .class_id = 0x00000000,
    .vendor_device_id = 0x10de0000,
    .probe = nvidia_probe,
    .remove = nvidia_remove,
    .shutdown = nvidia_shutdown,
    .flags = 0,
};

__attribute__((visibility("default"))) int dlmain() {
    NvlStatus status = nvlink_lib_initialize();
    if (status != NVL_SUCCESS) {
        printk("Failed to initialize nvlink lib\n");
        return -1;
    }
    if (!rm_init_rm(NULL)) {
        printk("NVIDIA_OPEN: rm_init_rm() failed!!!\n");
        return -1;
    }

    regist_pci_driver(&nvidia_pci_driver);

    return 0;
}
