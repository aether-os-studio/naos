#include "nvidia_open.h"

nvidia_device_t *nvidia_gpus[MAX_NVIDIA_GPU_NUM];
uint64_t nvidia_gpu_count = 0;

extern spinlock_t nvKmsLock;

const struct NvKmsKapiFunctionsTable *nvKms;

int nvidia_get_display_info(drm_device_t *drm_dev, uint32_t *width,
                            uint32_t *height, uint32_t *bpp) {
    struct limine_framebuffer *fb = get_current_fb();
    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;

    return 0;
}

int nvidia_get_fb(drm_device_t *drm_dev, uint32_t *width, uint32_t *height,
                  uint32_t *bpp, uint64_t *addr) {
    nvidia_device_t *nv_dev = (nvidia_device_t *)drm_dev->data;

    struct limine_framebuffer *fb = get_current_fb();
    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;
    *addr = (uint64_t)fb->address;

    return 0;
}

int nvidia_create_dumb(drm_device_t *drm_dev,
                       struct drm_mode_create_dumb *args) {
    nvidia_device_t *nv_dev = drm_dev->data;

    return 0;
}

int nvidia_destroy_dumb(drm_device_t *drm_dev, uint32_t handle) { return 0; }

int nvidia_dirty_fb(drm_device_t *drm_dev, struct drm_mode_fb_dirty_cmd *cmd) {
    return 0;
}

int nvidia_add_fb(drm_device_t *drm_dev, struct drm_mode_fb_cmd *cmd) {
    return 0;
}

int nvidia_add_fb2(drm_device_t *drm_dev, struct drm_mode_fb_cmd2 *cmd) {
    return 0;
}

int nvidia_set_plane(drm_device_t *drm_dev, struct drm_mode_set_plane *plane) {
    return 0;
}

int nvidia_atomic_commit(drm_device_t *drm_dev,
                         struct drm_mode_atomic *atomic) {
    return 0;
}

int nvidia_map_dumb(drm_device_t *drm_dev, struct drm_mode_map_dumb *args) {
    return 0;
}

int nvidia_set_crtc(drm_device_t *drm_dev, struct drm_mode_crtc *crtc) {
    return 0;
}

int nvidia_page_flip(struct drm_device *dev,
                     struct drm_mode_crtc_page_flip *flip) {
    return 0;
}

int nvidia_set_cursor(drm_device_t *drm_dev, struct drm_mode_cursor *cursor) {
    return 0;
}

int nvidia_gamma_set(drm_device_t *drm_dev, struct drm_mode_crtc_lut *gamma) {
    return 0;
}

int nvidia_get_connectors(drm_device_t *drm_dev, drm_connector_t **connectors,
                          uint32_t *count) {
    return 0;
}

int nvidia_get_crtcs(drm_device_t *drm_dev, drm_crtc_t **crtcs,
                     uint32_t *count) {
    return 0;
}

int nvidia_get_encoders(drm_device_t *drm_dev, drm_encoder_t **encoders,
                        uint32_t *count) {
    return 0;
}

int nvidia_get_planes(drm_device_t *drm_dev, drm_plane_t **planes,
                      uint32_t *count) {
    return 0;
}

// DRM device operations structure
drm_device_op_t nvidia_drm_device_op = {
    .get_display_info = nvidia_get_display_info,
    .get_fb = nvidia_get_fb,
    .create_dumb = nvidia_create_dumb,
    .destroy_dumb = nvidia_destroy_dumb,
    .dirty_fb = NULL, // Not implemented
    .add_fb = nvidia_add_fb,
    .add_fb2 = nvidia_add_fb2,
    .set_plane = NULL,     // Not implemented
    .atomic_commit = NULL, // Not implemented
    .map_dumb = nvidia_map_dumb,
    .set_crtc = nvidia_set_crtc,
    .page_flip = nvidia_page_flip,
    .set_cursor = nvidia_set_cursor,
    .gamma_set = NULL, // Not implemented
    .get_connectors = nvidia_get_connectors,
    .get_crtcs = nvidia_get_crtcs,
    .get_encoders = nvidia_get_encoders,
    .get_planes = nvidia_get_planes,
};

void nvidia_eventCallback(const struct NvKmsKapiEvent *event) {
    nvidia_device_t *nv_dev = (nvidia_device_t *)event->privateData;
    switch (event->type) {
    case NVKMS_EVENT_TYPE_DPY_CHANGED:
        break;
    case NVKMS_EVENT_TYPE_FLIP_OCCURRED:
        break;
    default:
        printk("nvidia_open: Unhandled event type %d\n", event->type);
    }
    return;
}

nvidia_stack_t *sp[5] = {NULL, NULL, NULL, NULL, NULL};

int nvidia_probe(pci_device_t *dev, uint32_t vendor_device_id) {
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

    nvidia_device_t *nv_dev = malloc(sizeof(nvidia_device_t));
    memset(nv_dev, 0, sizeof(nvidia_device_t));

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
    nv_dev->nv_.handle = nv_dev;
    nv_dev->nv_.cpu_numa_node_id = -1;
    nv_dev->nv_.interrupt_line = 0;

    size_t nvBarIndex = 0;

    for (size_t i = 0; i < 6; i++) {
        if (dev->bars[i].address && dev->bars[i].mmio) {
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

    nvidia_gpus[nvidia_gpu_count] = nv_dev;
    nvidia_gpu_count++;

    NV_STATUS status = rm_is_supported_device(NULL, &nv_dev->nv_);
    if (status != NV_OK) {
        free(nv_dev);
        printk("Failed detect support device!!!\n");
        return -1;
    }

    bool success = rm_init_private_state(NULL, &nv_dev->nv_);
    if (!success) {
        free(nv_dev);
        printk("Failed init private state!!!\n");
        return -1;
    }

    rm_set_rm_firmware_requested(NULL, &nv_dev->nv_);
    rm_enable_dynamic_power_management(NULL, &nv_dev->nv_);

    rm_notify_gpu_addition(NULL, &nv_dev->nv_);

    rm_unref_dynamic_power(NULL, &nv_dev->nv_, NV_DYNAMIC_PM_FINE);

    nvKmsLock.lock = 0;

    static struct NvKmsKapiFunctionsTable nvKmsFuncsTable = {
        .versionString = "575.51.02",
    };

    nvKms = &nvKmsFuncsTable;

    if (!nvKmsKapiGetFunctionsTableInternal(&nvKmsFuncsTable)) {
        free(nv_dev);
        return -1;
    }

    struct NvKmsKapiAllocateDeviceParams params = {
        .gpuId = nv_dev->nv_.gpu_id,
        .privateData = nv_dev,
        .eventCallback = nvidia_eventCallback,
    };

    nv_dev->kmsdev = nvKms->allocateDevice(&params);
    if (!nv_dev->kmsdev) {
        free(nv_dev);
        printk("Failed to allocate kms device!!!\n");
        return -1;
    }

    if (!nvKms->grabOwnership(nv_dev->kmsdev)) {
        free(nv_dev);
        return -1;
    }

    nvKms->framebufferConsoleDisabled(nv_dev->kmsdev);

    struct NvKmsKapiDeviceResourcesInfo resInfo;
    if (!nvKms->getDeviceResourcesInfo(nv_dev->kmsdev, &resInfo)) {
        free(nv_dev);
        return -1;
    }

    // // setup CRTCs and planes
    // setupCrtcAndPlanes(resInfo);

    // // setup Connectors and Encoders
    // setupConnectorsAndEncoders();

    success = nvKms->declareEventInterest(
        nv_dev->kmsdev, ((1 << NVKMS_EVENT_TYPE_DPY_CHANGED) |
                         (1 << NVKMS_EVENT_TYPE_DYNAMIC_DPY_CONNECTED) |
                         (1 << NVKMS_EVENT_TYPE_FLIP_OCCURRED)));

    if (!success) {
        free(nv_dev);
        return -1;
    }

    drm_resource_manager_init(&nv_dev->resource_mgr);

    NvU32 nDisplays;
    NvKmsKapiDisplay hDisplays[16];
    success = nvKms->getDisplays(nv_dev->kmsdev, &nDisplays, hDisplays);
    if (!success) {
        free(nv_dev);
        return -1;
    }

    for (size_t i = 0; i < nDisplays; i++) {
        struct limine_framebuffer *fb = get_current_fb();

        // Create connector
        nv_dev->connectors[i] = drm_connector_alloc(
            &nv_dev->resource_mgr, DRM_MODE_CONNECTOR_VIRTUAL, nv_dev);
        if (nv_dev->connectors[i]) {
            nv_dev->connectors[i]->connection = DRM_MODE_CONNECTED;
            nv_dev->connectors[i]->mm_width = fb->width;
            nv_dev->connectors[i]->mm_height = fb->height;

            // Add display mode
            nv_dev->connectors[i]->modes =
                malloc(sizeof(struct drm_mode_modeinfo));

            struct drm_mode_modeinfo mode = {
                .clock = fb->width * 60,
                .hdisplay = fb->width,
                .hsync_start = fb->width + 16,
                .hsync_end = fb->width + 16 + 96,
                .htotal = fb->width + 16 + 96 + 48,
                .vdisplay = fb->height,
                .vsync_start = fb->height + 10,
                .vsync_end = fb->height + 10 + 2,
                .vtotal = fb->height + 10 + 2 + 33,
                .vrefresh = 60,
            };

            memcpy(nv_dev->connectors[i]->modes, &mode,
                   sizeof(struct drm_mode_modeinfo));
            nv_dev->connectors[i]->count_modes = 1;
        }

        // Create CRTC
        nv_dev->crtcs[i] = drm_crtc_alloc(&nv_dev->resource_mgr, nv_dev);

        // Create encoder
        nv_dev->encoders[i] = drm_encoder_alloc(
            &nv_dev->resource_mgr, DRM_MODE_ENCODER_VIRTUAL, nv_dev);

        if (nv_dev->encoders[i] && nv_dev->connectors[i] && nv_dev->crtcs[i]) {
            nv_dev->encoders[i]->possible_crtcs = 1 << i;
            nv_dev->connectors[i]->encoder_id = nv_dev->encoders[i]->id;
            nv_dev->connectors[i]->crtc_id = nv_dev->crtcs[i]->id;
        }
    }

    drm_regist_pci_dev(nv_dev, &nvidia_drm_device_op, nv_dev->pci_dev);

    return 0;
}

void nvidia_remove(pci_device_t *dev) {}

void nvidia_shutdown(pci_device_t *dev) {}

NvBool nvidia_open_do_open_gpu(nvidia_device_t *dev) {
    if (dev->nv_.flags & NV_FLAG_OPEN)
        return NV_FALSE;

    if (!dev->adapterInitialized_) {
        rm_ref_dynamic_power(NULL, &dev->nv_, NV_DYNAMIC_PM_COARSE);

        bool success = rm_init_adapter(NULL, &dev->nv_);
        if (!success)
            return NV_FALSE;

        dev->adapterInitialized_ = true;
    }

    dev->nv_.flags |= NV_FLAG_OPEN;

    rm_request_dnotifier_state(NULL, &dev->nv_);

    return NV_TRUE;
}

NvBool nvidia_open_open_gpu(NvU32 gpuId) {
    for (uint64_t i = 0; i < nvidia_gpu_count; i++) {
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
    .flags = PCI_DRIVER_FLAGS_NEED_SYSFS,
};

__attribute__((visibility("default"))) int dlmain() {
    NvlStatus status = nvlink_lib_initialize();
    if (status != NVL_SUCCESS) {
        printk("Failed to initialize nvlink lib\n");
        return -1;
    }

    if (!rm_init_rm(*sp)) {
        printk("NVIDIA_OPEN: rm_init_rm() failed!!!\n");
        return -1;
    }

    regist_pci_driver(&nvidia_pci_driver);

    return 0;
}