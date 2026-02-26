#pragma once

#include <libs/aether/stdio.h>
#include <libs/aether/pci.h>
#include <libs/aether/drm.h>
#include <libs/aether/task.h>

#define NV_FIRMWARE_FOR_NAME(name) "/lib/firmware/nvidia/575.51.02/" name ".bin"

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
    bool in_use;
    uint32_t handle;
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t format;
    uint64_t modifier;
    uint64_t size;
    uint64_t map_offset;
    uint32_t refcount;
    struct NvKmsKapiMemory *memory;
    struct NvKmsKapiSurface *surface;
} nvidia_fb_t;

typedef struct nvidia_device {
    pci_device_t *pci_dev;
    spinlock_t timerLock;
    nv_state_t nv_;
    struct NvKmsKapiDevice *kmsdev;

    bool adapterInitialized_;
    bool shouldEnableIrq;

    bool tasks_should_exit;
    task_t *timer_task;
    task_t *irq_handler_task;

    // DRM resources
    drm_device_t *drm_dev;
    drm_connector_t *connectors[16];
    drm_crtc_t *crtcs[16];
    drm_encoder_t *encoders[16];
    drm_plane_t *planes[16];
    drm_resource_manager_t resource_mgr;
    uint32_t num_displays;
    NvKmsKapiDisplay displays[16];
    uint32_t display_heads[16];
    int8_t head_to_crtc[NVKMS_KAPI_MAX_HEADS];
    uint32_t num_crtcs;
    uint32_t pitch_alignment;
    bool has_video_memory;
    uint64_t pending_flip_user_data[NVKMS_KAPI_MAX_HEADS];
    bool pending_flip_event[NVKMS_KAPI_MAX_HEADS];

    nvidia_fb_t framebuffers[32];
} nvidia_device_t;

extern NvBool nvidia_open_open_gpu(NvU32 gpuId);

#define MAX_NVIDIA_GPU_NUM 4
