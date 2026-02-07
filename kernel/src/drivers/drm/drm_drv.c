#include <drivers/drm/drm.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm_ioctl.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <arch/arch.h>
#include <mm/mm.h>
#include <libs/klibc.h>

/**
 * drm_read - Read from DRM device
 * @data: DRM device pointer
 * @buf: User buffer
 * @offset: Offset in file
 * @len: Length to read
 * @flags: File flags
 *
 * Handles reading of DRM events (vblank, flip complete, etc.)
 */
ssize_t drm_read(void *data, void *buf, uint64_t offset, uint64_t len,
                 uint64_t flags) {
    drm_device_t *dev = (drm_device_t *)data;

    while (!dev->drm_events[0]) {
        if (flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        schedule(SCHED_FLAG_YIELD);
    }

    struct drm_event_vblank vbl = {
        .base.type = dev->drm_events[0]->type,
        .base.length = sizeof(vbl),
        .user_data = dev->drm_events[0]->user_data,
        .tv_sec = nano_time() / 1000000000,
        .tv_usec = (nano_time() % 1000000000) / 1000,
        .crtc_id =
            dev->resource_mgr.crtcs[0] ? dev->resource_mgr.crtcs[0]->id : 0,
    };

    free(dev->drm_events[0]);
    dev->drm_events[0] = NULL;

    memmove(&dev->drm_events[0], &dev->drm_events[1],
            sizeof(struct k_drm_event *) * (DRM_MAX_EVENTS_COUNT - 1));

    ssize_t ret = 0;

    if (len >= sizeof(vbl)) {
        memcpy(buf, &vbl, sizeof(vbl));
        ret = sizeof(vbl);
    } else {
        ret = -EINVAL;
    }

    return ret;
}

/**
 * drm_poll - Poll DRM device for events
 * @data: DRM device pointer
 * @event: Poll events to check
 *
 * Returns events that are ready
 */
ssize_t drm_poll(void *data, size_t event) {
    drm_device_t *dev = (drm_device_t *)data;
    ssize_t revent = 0;

    if (event & EPOLLIN) {
        if (dev->drm_events[0]) {
            revent |= EPOLLIN;
        }
    }

    return revent;
}

/**
 * drm_map - Map DRM buffer to user space
 * @data: DRM device pointer
 * @addr: User address to map to
 * @offset: Offset in buffer
 * @len: Length to map
 *
 * Maps a DRM buffer (typically a dumb buffer) to user space
 */
void *drm_map(void *data, void *addr, uint64_t offset, uint64_t len) {
    drm_device_t *dev = (drm_device_t *)data;
    (void)dev; // Not used for now

    map_page_range(get_current_page_dir(true), (uint64_t)addr, offset, len,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

/**
 * drm_device_init - Initialize a DRM device
 * @dev: DRM device to initialize
 * @data: Driver private data
 * @op: Driver operations
 *
 * Initializes the basic fields of a DRM device
 */
static void drm_device_init(drm_device_t *dev, void *data,
                            drm_device_op_t *op) {
    memset(dev, 0, sizeof(drm_device_t));
    // ID initialize after device registed
    dev->data = data;
    dev->op = op;

    // Initialize resource manager
    drm_resource_manager_init(&dev->resource_mgr);
}

/**
 * drm_device_setup_sysfs - Setup sysfs entries for DRM device
 * @major: DRM device major
 * @minor: DRM device minor
 * @dev: DRM device
 * @pci_dev: PCI device (can be NULL for non-PCI devices)
 * @dev_name: Device name (e.g., "card0")
 *
 * Creates sysfs entries for the DRM device
 */
static void drm_device_setup_sysfs(int major, int minor, drm_device_t *dev,
                                   pci_device_t *pci_dev,
                                   const char *dev_name) {
    // If PCI device, create PCI-specific entries
    if (pci_dev) {
        vfs_node_t dev_root = sysfs_regist_dev('c', major, minor, "", dev_name,
                                               "SUBSYSTEM=drm\n");

        vfs_node_t dev = sysfs_child_append(dev_root, "device", true);

        vfs_node_t drm = sysfs_child_append(dev, "drm", true);

        vfs_node_t dev_uevent = sysfs_child_append(dev, "uevent", false);

        char content[64];
        sprintf(content, "PCI_SLOT_NAME=%04x:%02x:%02x.%u\n", pci_dev->segment,
                pci_dev->bus, pci_dev->slot, pci_dev->func);
        vfs_write(dev_uevent, content, 0, strlen(content));

        vfs_node_t dev_vendor = sysfs_child_append(dev, "vendor", false);
        sprintf(content, "0x%04x\n", pci_dev->vendor_id);
        vfs_write(dev_vendor, content, 0, strlen(content));

        vfs_node_t dev_subsystem_vendor =
            sysfs_child_append(dev, "subsystem_vendor", false);
        sprintf(content, "0x%04x\n", pci_dev->subsystem_vendor_id);
        vfs_write(dev_subsystem_vendor, content, 0, strlen(content));

        vfs_node_t dev_device = sysfs_child_append(dev, "device", false);
        sprintf(content, "0x%04x\n", pci_dev->device_id);
        vfs_write(dev_device, content, 0, strlen(content));

        vfs_node_t dev_subsystem_device =
            sysfs_child_append(dev, "subsystem_device", false);
        sprintf(content, "0x%04x\n", pci_dev->subsystem_device_id);
        vfs_write(dev_subsystem_device, content, 0, strlen(content));

        vfs_node_t version = sysfs_child_append(drm, "version", false);
        sprintf(content, "drm 1.1.0 20060810");
        vfs_write(version, content, 0, strlen(content));

        char buf[8];
        sprintf(buf, "card%d", minor);
        vfs_node_t cardn = sysfs_child_append(drm, (const char *)buf, true);

        char path[256];
        sprintf(path, "/sys/dev/char/%d:%d/device/drm/card%d", major, minor,
                minor);

        vfs_node_t class_drm = vfs_open("/sys/class/drm", 0);
        sprintf(buf, "card%d", minor);
        vfs_node_t class_drm_cardn =
            sysfs_child_append_symlink(class_drm, buf, path);

        vfs_node_t uevent = sysfs_child_append(cardn, "uevent", false);
        sprintf(content,
                "MAJOR=%d\nMINOR=%d\nDEVNAME=dri/card%d\nSUBSYSTEM=drm\n",
                major, minor, minor);
        vfs_write(uevent, content, 0, strlen(content));

        sysfs_child_append_symlink(cardn, "subsystem", "/sys/class/drm");
        sysfs_child_append_symlink(dev, "subsystem", "/sys/bus/pci");
    }
}

static int drm_id = 0;

/**
 * drm_register_device - Register a DRM device with the system
 * @data: Driver private data
 * @op: Driver operations
 * @name: Base name for the device
 * @pci_dev: PCI device (optional, can be NULL for non-PCI devices)
 *
 * Registers a new DRM device and returns the device structure.
 * The caller is responsible for freeing the device when it's no longer needed.
 */
drm_device_t *drm_register_device(void *data, drm_device_op_t *op,
                                  const char *name, pci_device_t *pci_dev) {
    char dev_name[32];
    sprintf(dev_name, "%s%d", name, drm_id);

    // Allocate and initialize DRM device
    drm_device_t *dev = malloc(sizeof(drm_device_t));
    if (!dev) {
        printk("drm: Failed to allocate DRM device\n");
        return NULL;
    }

    // Register character device
    uint64_t dev_nr =
        device_install(DEV_CHAR, DEV_GPU, dev, dev_name, 0, drm_ioctl, drm_poll,
                       drm_read, NULL, drm_map);

    drm_device_init(dev, data, op);
    dev->id = dev_nr & 0xFF;

    dev->data = data;
    dev->op = op;

    // Populate hardware resources if driver supports it
    if (dev->op->get_connectors) {
        drm_connector_t *connectors[DRM_MAX_CONNECTORS_PER_DEVICE];
        memset(connectors, 0, sizeof(connectors));
        uint32_t connector_count = 0;
        if (dev->op->get_connectors(dev, connectors, &connector_count) == 0) {
            for (uint32_t i = 0;
                 i < connector_count && i < DRM_MAX_CONNECTORS_PER_DEVICE;
                 i++) {
                if (connectors[i]) {
                    uint32_t slot = drm_find_free_slot(
                        (void **)dev->resource_mgr.connectors,
                        DRM_MAX_CONNECTORS_PER_DEVICE);
                    if (slot != (uint32_t)-1) {
                        dev->resource_mgr.connectors[slot] = connectors[i];
                        connectors[i]->id =
                            dev->resource_mgr.next_connector_id++;
                    }
                }
            }
        }
    }

    if (dev->op->get_crtcs) {
        drm_crtc_t *crtcs[DRM_MAX_CRTCS_PER_DEVICE];
        memset(crtcs, 0, sizeof(crtcs));
        uint32_t crtc_count = 0;
        if (dev->op->get_crtcs(dev, crtcs, &crtc_count) == 0) {
            for (uint32_t i = 0; i < crtc_count && i < DRM_MAX_CRTCS_PER_DEVICE;
                 i++) {
                if (crtcs[i]) {
                    uint32_t slot =
                        drm_find_free_slot((void **)dev->resource_mgr.crtcs,
                                           DRM_MAX_CRTCS_PER_DEVICE);
                    if (slot != (uint32_t)-1) {
                        dev->resource_mgr.crtcs[slot] = crtcs[i];
                        crtcs[i]->id = dev->resource_mgr.next_crtc_id++;
                    }
                }
            }
        }
    }

    if (dev->op->get_encoders) {
        drm_encoder_t *encoders[DRM_MAX_ENCODERS_PER_DEVICE];
        memset(encoders, 0, sizeof(encoders));
        uint32_t encoder_count = 0;
        if (dev->op->get_encoders(dev, encoders, &encoder_count) == 0) {
            for (uint32_t i = 0;
                 i < encoder_count && i < DRM_MAX_ENCODERS_PER_DEVICE; i++) {
                if (encoders[i]) {
                    uint32_t slot =
                        drm_find_free_slot((void **)dev->resource_mgr.encoders,
                                           DRM_MAX_ENCODERS_PER_DEVICE);
                    if (slot != (uint32_t)-1) {
                        dev->resource_mgr.encoders[slot] = encoders[i];
                        encoders[i]->id = dev->resource_mgr.next_encoder_id++;
                    }
                }
            }
        }
    }

    if (dev->op->get_planes) {
        drm_plane_t *planes[DRM_MAX_PLANES_PER_DEVICE];
        memset(planes, 0, sizeof(planes));
        uint32_t plane_count = 0;
        if (dev->op->get_planes(dev, planes, &plane_count) == 0) {
            for (uint32_t i = 0;
                 i < plane_count && i < DRM_MAX_PLANES_PER_DEVICE; i++) {
                if (planes[i]) {
                    uint32_t slot =
                        drm_find_free_slot((void **)dev->resource_mgr.planes,
                                           DRM_MAX_PLANES_PER_DEVICE);
                    if (slot != (uint32_t)-1) {
                        dev->resource_mgr.planes[slot] = planes[i];
                        planes[i]->id = dev->resource_mgr.next_plane_id++;
                    }
                }
            }
        }
    }

    // If no hardware resources were found, create default ones
    if (!dev->resource_mgr.connectors[0]) {
        drm_connector_t *connector = drm_connector_alloc(
            &dev->resource_mgr, DRM_MODE_CONNECTOR_VIRTUAL, NULL);
        if (connector) {
            connector->connection = DRM_MODE_CONNECTED;
            connector->count_modes = 1;
            connector->modes = malloc(sizeof(struct drm_mode_modeinfo));
            if (connector->modes) {
                uint32_t width, height, bpp;
                dev->op->get_display_info(dev, &width, &height, &bpp);

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
                sprintf(mode.name, "%dx%d", width, height);
                memcpy(connector->modes, &mode,
                       sizeof(struct drm_mode_modeinfo));
            }
        }
    }

    if (!dev->resource_mgr.crtcs[0]) {
        drm_crtc_t *crtc = drm_crtc_alloc(&dev->resource_mgr, NULL);
        // CRTC will be configured when used
    }

    if (!dev->resource_mgr.encoders[0]) {
        drm_encoder_t *encoder = drm_encoder_alloc(
            &dev->resource_mgr, DRM_MODE_ENCODER_VIRTUAL, NULL);
        if (encoder && dev->resource_mgr.connectors[0] &&
            dev->resource_mgr.crtcs[0]) {
            encoder->possible_crtcs = 1;
            dev->resource_mgr.connectors[0]->encoder_id = encoder->id;
        }
    }

    drm_framebuffer_t *framebuffer =
        drm_framebuffer_alloc(&dev->resource_mgr, NULL);
    uint32_t width, height, bpp;
    dev->op->get_display_info(dev, &width, &height, &bpp);
    framebuffer->width = width;
    framebuffer->height = height;
    framebuffer->bpp = bpp;
    framebuffer->pitch = width * sizeof(uint32_t);
    framebuffer->depth = 24;

    // Setup sysfs entries
    drm_device_setup_sysfs((dev_nr >> 8) & 0xFF, dev_nr & 0xFF, dev, pci_dev,
                           dev_name);

    drm_id++;

    return dev;
}

/**
 * drm_regist_pci_dev - Register a PCI-based DRM device (legacy API)
 * @data: Driver private data
 * @op: Driver operations
 * @pci_dev: PCI device
 *
 * This is the legacy API for backwards compatibility.
 * New drivers should use drm_register_device() instead.
 */
drm_device_t *drm_regist_pci_dev(void *data, drm_device_op_t *op,
                                 pci_device_t *pci_dev) {
    return drm_register_device(data, op, "dri/card", pci_dev);
}

/**
 * drm_unregister_device - Unregister a DRM device
 * @dev: DRM device to unregister
 *
 * Unregisters a DRM device and frees its resources.
 * The device must not be used after this call.
 */
void drm_unregister_device(drm_device_t *dev) {
    if (!dev)
        return;

    // Clean up resource manager
    drm_resource_manager_cleanup(&dev->resource_mgr);

    // Free any pending events
    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++) {
        if (dev->drm_events[i]) {
            free(dev->drm_events[i]);
        }
    }

    free(dev);
}

/**
 * drm_init_after_pci_sysfs - Initialize fallback DRM device
 *
 * Initializes a plain framebuffer DRM device if no GPU is found.
 * This provides basic display functionality even without hardware acceleration.
 */
void drm_init_after_pci_sysfs() {
    if (!vfs_open("/dev/dri/card0", 0)) {
        printk("Cannot find GPU device, using framebuffer.\n");
        extern void drm_plainfb_init(void);
        drm_plainfb_init();
    }
}

/**
 * drm_post_event - Post an event to the DRM device
 * @dev: DRM device
 * @type: Event type (DRM_EVENT_VBLANK, DRM_EVENT_FLIP_COMPLETE, etc.)
 * @user_data: User data to include with the event
 *
 * Posts an event to the DRM device's event queue.
 * Returns 0 on success, -ENOSPC if the event queue is full.
 */
int drm_post_event(drm_device_t *dev, uint32_t type, uint64_t user_data) {
    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++) {
        if (!dev->drm_events[i]) {
            dev->drm_events[i] = malloc(sizeof(struct k_drm_event));
            if (!dev->drm_events[i]) {
                return -ENOMEM;
            }

            dev->drm_events[i]->type = type;
            dev->drm_events[i]->user_data = user_data;
            dev->drm_events[i]->timestamp.tv_sec = nano_time() / 1000000000ULL;
            dev->drm_events[i]->timestamp.tv_nsec = nano_time() % 1000000000ULL;

            return 0;
        }
    }

    return -ENOSPC;
}
