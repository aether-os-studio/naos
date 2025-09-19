#pragma once

#include <libs/aether/stdio.h>
#include <libs/aether/pci.h>
#include <libs/aether/drm.h>

#include <nvtypes.h>
#include <nv.h>
#include <nv-reg.h>
#include <nvlink_export.h>
#include <nvkms.h>
#include <nvkms-kapi.h>
#include <nvkms-rmapi.h>
#include <nvkms-api.h>
#include <nvkms-utils.h>
#include <os-interface.h>

typedef struct nvidia_fb {
    int fb_id;
    struct NvKmsKapiSurface *pSurface;
} nvidia_fb_t;

typedef struct nvidia_device {
    pci_device_t *pci_dev;
    pci_bar_t *nv_bars[6];
    spinlock_t timerLock;
    nv_state_t nv_;
    uint64_t regs;
    uint64_t fb;
    struct NvKmsKapiDevice *kmsdev;

    // DRM resources
    drm_connector_t *connectors[16];
    drm_crtc_t *crtcs[16];
    drm_encoder_t *encoders[16];
    drm_resource_manager_t resource_mgr;

    nvidia_fb_t *framebuffers[16];
} nvidia_device_t;
