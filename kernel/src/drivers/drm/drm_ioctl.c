/*
 * DRM ioctl implementation
 *
 * This file contains the implementation of DRM ioctl handling functions.
 * It separates the ioctl implementation from the core driver framework.
 */

#include <drivers/drm/drm.h>
#include <drivers/drm/drm_ioctl.h>
#include <drivers/drm/drm_core.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/proc.h>
#include <fs/vfs/vfs.h>
#include <mm/mm.h>
#include <task/task.h>

static ssize_t drm_copy_to_user_ptr(uint64_t user_ptr, const void *src,
                                    size_t size) {
    if (!user_ptr || size == 0) {
        return 0;
    }

    if (copy_to_user((void *)(uintptr_t)user_ptr, src, size)) {
        return -EFAULT;
    }

    return 0;
}

#define DRM_MAX_PRIME_EXPORTS 256
#define DRM_MAX_DUMB_EXPORTS 512
#define DRM_MAX_USER_BLOBS 256
#define DRM_USER_BLOB_MAX_SIZE (64 * 1024)
#define DRM_BLOB_ID_USER_BASE 0x30000000U
#define DRM_BLOB_ID_USER_LAST 0x3fffffffU

typedef struct drm_prime_export_entry {
    bool used;
    drm_device_t *dev;
    uint64_t inode;
    uint32_t handle;
} drm_prime_export_entry_t;

static drm_prime_export_entry_t drm_prime_exports[DRM_MAX_PRIME_EXPORTS];
static spinlock_t drm_prime_exports_lock = SPIN_INIT;

typedef struct drm_prime_fd_ctx {
    vfs_node_t node;
    drm_device_t *dev;
    uint32_t handle;
    uint64_t phys;
    uint64_t size;
} drm_prime_fd_ctx_t;

static int drm_prime_fsid = 0;
static spinlock_t drm_prime_fsid_lock = SPIN_INIT;

static ssize_t drm_primefd_read(fd_t *fd, void *buf, uint64_t offset,
                                uint64_t len) {
    drm_prime_fd_ctx_t *ctx = fd->node->handle;
    if (!ctx || !buf || offset >= ctx->size) {
        return 0;
    }

    uint64_t copy_len = MIN(len, ctx->size - offset);
    memcpy(buf, (void *)(uintptr_t)phys_to_virt(ctx->phys + offset), copy_len);
    return (ssize_t)copy_len;
}

static ssize_t drm_primefd_write(fd_t *fd, const void *buf, uint64_t offset,
                                 uint64_t len) {
    drm_prime_fd_ctx_t *ctx = fd->node->handle;
    if (!ctx || !buf || offset >= ctx->size) {
        return 0;
    }

    uint64_t copy_len = MIN(len, ctx->size - offset);
    memcpy((void *)(uintptr_t)phys_to_virt(ctx->phys + offset), buf, copy_len);
    return (ssize_t)copy_len;
}

static bool drm_primefd_close(vfs_node_t node) {
    drm_prime_fd_ctx_t *ctx = node ? node->handle : NULL;
    if (!ctx) {
        return true;
    }

    free(ctx);
    return true;
}

static int drm_primefd_stat(vfs_node_t node) {
    drm_prime_fd_ctx_t *ctx = node ? node->handle : NULL;
    if (!ctx) {
        return -EINVAL;
    }
    node->size = ctx->size;
    return 0;
}

static void drm_primefd_resize(vfs_node_t node, uint64_t size) {
    drm_prime_fd_ctx_t *ctx = node ? node->handle : NULL;
    if (!ctx) {
        return;
    }

    ctx->size = MIN(size, ctx->size);
    if (ctx->node) {
        ctx->node->size = ctx->size;
    }
}

static void *drm_primefd_map(fd_t *file, void *addr, size_t offset, size_t size,
                             size_t prot, size_t flags) {
    (void)prot;
    (void)flags;

    drm_prime_fd_ctx_t *ctx = file->node->handle;
    if (!ctx || offset >= ctx->size || size == 0) {
        return (void *)-EINVAL;
    }

    size_t map_size = MIN(size, (size_t)(ctx->size - offset));
    if (map_size == 0) {
        return (void *)-EINVAL;
    }

    map_page_range(get_current_page_dir(true), (uint64_t)addr,
                   ctx->phys + offset, map_size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

static vfs_operations_t drm_primefs_callbacks = {
    .close = drm_primefd_close,
    .read = drm_primefd_read,
    .write = drm_primefd_write,
    .map = drm_primefd_map,
    .stat = drm_primefd_stat,
    .resize = drm_primefd_resize,
    .free_handle = vfs_generic_free_handle,
};

static fs_t drm_primefs = {
    .name = "drmprimefs",
    .magic = 0,
    .ops = &drm_primefs_callbacks,
    .flags = FS_FLAGS_HIDDEN | FS_FLAGS_VIRTUAL,
};

static int drm_primefd_ensure_registered(void) {
    if (drm_prime_fsid > 0) {
        return 0;
    }

    spin_lock(&drm_prime_fsid_lock);
    if (drm_prime_fsid == 0) {
        drm_prime_fsid = vfs_regist(&drm_primefs);
    }
    spin_unlock(&drm_prime_fsid_lock);

    return drm_prime_fsid > 0 ? 0 : -ENOMEM;
}

static ssize_t drm_primefd_create(drm_device_t *dev, uint32_t handle,
                                  uint64_t phys, uint64_t size,
                                  uint32_t flags) {
    int ret = drm_primefd_ensure_registered();
    if (ret) {
        return ret;
    }

    int fd = -1;
    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (!current_task->fd_info->fds[i]) {
                fd = i;
                break;
            }
        }
    });

    if (fd < 0) {
        return -EMFILE;
    }

    drm_prime_fd_ctx_t *ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->dev = dev;
    ctx->handle = handle;
    ctx->phys = phys;
    ctx->size = size;

    fd_t *fd_obj = malloc(sizeof(fd_t));
    if (!fd_obj) {
        free(ctx);
        return -ENOMEM;
    }
    memset(fd_obj, 0, sizeof(*fd_obj));

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    if (!node) {
        free(fd_obj);
        free(ctx);
        return -ENOMEM;
    }

    node->type = file_none;
    node->fsid = drm_prime_fsid;
    node->handle = ctx;
    node->refcount++;
    node->size = size;
    ctx->node = node;

    fd_obj->node = node;
    fd_obj->offset = 0;
    fd_obj->flags = O_RDWR | flags;
    fd_obj->close_on_exec = !!(flags & DRM_CLOEXEC);

    with_fd_info_lock(current_task->fd_info, {
        if (!current_task->fd_info->fds[fd]) {
            current_task->fd_info->fds[fd] = fd_obj;
            procfs_on_open_file(current_task, fd);
        } else {
            free(fd_obj);
            fd_obj = NULL;
        }
    });

    if (!fd_obj) {
        vfs_close(node);
        return -EMFILE;
    }

    return fd;
}

static ssize_t drm_prime_get_handle_phys(drm_device_t *dev, uint32_t handle,
                                         uint64_t *phys) {
    if (!dev || !dev->op || !dev->op->map_dumb || !phys) {
        return -ENOSYS;
    }

    struct drm_mode_map_dumb map = {0};
    map.handle = handle;

    int ret = dev->op->map_dumb(dev, &map);
    if (ret) {
        return ret;
    }

    *phys = map.offset;
    return 0;
}

typedef struct drm_dumb_export_entry {
    bool used;
    drm_device_t *dev;
    uint32_t handle;
    uint64_t size;
} drm_dumb_export_entry_t;

static drm_dumb_export_entry_t drm_dumb_exports[DRM_MAX_DUMB_EXPORTS];
static spinlock_t drm_dumb_exports_lock = SPIN_INIT;

typedef struct drm_user_blob_entry {
    bool used;
    drm_device_t *dev;
    uint32_t blob_id;
    uint32_t length;
    void *data;
} drm_user_blob_entry_t;

static drm_user_blob_entry_t drm_user_blobs[DRM_MAX_USER_BLOBS];
static spinlock_t drm_user_blobs_lock = SPIN_INIT;
static uint32_t drm_user_blob_next_id = DRM_BLOB_ID_USER_BASE + 1;

static ssize_t drm_prime_get_fd_inode(int fd, uint64_t *inode) {
    if (fd < 0 || fd >= MAX_FD_NUM || !inode) {
        return -EBADF;
    }

    int ret = -EBADF;
    with_fd_info_lock(current_task->fd_info, {
        if (current_task->fd_info->fds[fd] &&
            current_task->fd_info->fds[fd]->node) {
            *inode = current_task->fd_info->fds[fd]->node->inode;
            ret = 0;
        }
    });

    return ret;
}

static ssize_t drm_prime_store_export(drm_device_t *dev, uint64_t inode,
                                      uint32_t handle) {
    int free_slot = -1;

    spin_lock(&drm_prime_exports_lock);
    for (int i = 0; i < DRM_MAX_PRIME_EXPORTS; i++) {
        if (drm_prime_exports[i].used) {
            if (!vfs_find_node_by_inode(drm_prime_exports[i].inode)) {
                memset(&drm_prime_exports[i], 0, sizeof(drm_prime_exports[i]));
                if (free_slot < 0) {
                    free_slot = i;
                }
                continue;
            }

            if (drm_prime_exports[i].dev == dev &&
                drm_prime_exports[i].inode == inode) {
                drm_prime_exports[i].handle = handle;
                spin_unlock(&drm_prime_exports_lock);
                return 0;
            }
            continue;
        }

        if (free_slot < 0) {
            free_slot = i;
        }
    }

    if (free_slot < 0) {
        spin_unlock(&drm_prime_exports_lock);
        return -ENOSPC;
    }

    drm_prime_exports[free_slot].used = true;
    drm_prime_exports[free_slot].dev = dev;
    drm_prime_exports[free_slot].inode = inode;
    drm_prime_exports[free_slot].handle = handle;
    spin_unlock(&drm_prime_exports_lock);

    return 0;
}

static ssize_t drm_prime_lookup_handle(drm_device_t *dev, uint64_t inode,
                                       uint32_t *handle) {
    spin_lock(&drm_prime_exports_lock);
    for (int i = 0; i < DRM_MAX_PRIME_EXPORTS; i++) {
        if (!drm_prime_exports[i].used) {
            continue;
        }
        if (drm_prime_exports[i].dev != dev ||
            drm_prime_exports[i].inode != inode) {
            continue;
        }

        *handle = drm_prime_exports[i].handle;
        spin_unlock(&drm_prime_exports_lock);
        return 0;
    }
    spin_unlock(&drm_prime_exports_lock);

    return -EBADF;
}

static void drm_dumb_store_size(drm_device_t *dev, uint32_t handle,
                                uint64_t size) {
    int free_slot = -1;

    spin_lock(&drm_dumb_exports_lock);
    for (int i = 0; i < DRM_MAX_DUMB_EXPORTS; i++) {
        if (drm_dumb_exports[i].used) {
            if (drm_dumb_exports[i].dev == dev &&
                drm_dumb_exports[i].handle == handle) {
                drm_dumb_exports[i].size = size;
                spin_unlock(&drm_dumb_exports_lock);
                return;
            }
            continue;
        }

        if (free_slot < 0) {
            free_slot = i;
        }
    }

    if (free_slot >= 0) {
        drm_dumb_exports[free_slot].used = true;
        drm_dumb_exports[free_slot].dev = dev;
        drm_dumb_exports[free_slot].handle = handle;
        drm_dumb_exports[free_slot].size = size;
    }
    spin_unlock(&drm_dumb_exports_lock);
}

static uint64_t drm_dumb_get_size(drm_device_t *dev, uint32_t handle) {
    uint64_t size = 0;

    spin_lock(&drm_dumb_exports_lock);
    for (int i = 0; i < DRM_MAX_DUMB_EXPORTS; i++) {
        if (!drm_dumb_exports[i].used) {
            continue;
        }
        if (drm_dumb_exports[i].dev == dev &&
            drm_dumb_exports[i].handle == handle) {
            size = drm_dumb_exports[i].size;
            break;
        }
    }
    spin_unlock(&drm_dumb_exports_lock);

    if (size != 0) {
        return size;
    }

    for (uint32_t i = 0; i < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; i++) {
        drm_framebuffer_t *fb = dev->resource_mgr.framebuffers[i];
        if (!fb || fb->handle != handle) {
            continue;
        }
        if (fb->pitch && fb->height) {
            return (uint64_t)fb->pitch * (uint64_t)fb->height;
        }
    }

    return 0;
}

static ssize_t drm_user_blob_find_index_locked(drm_device_t *dev,
                                               uint32_t blob_id) {
    for (int i = 0; i < DRM_MAX_USER_BLOBS; i++) {
        if (!drm_user_blobs[i].used) {
            continue;
        }
        if (drm_user_blobs[i].dev == dev &&
            drm_user_blobs[i].blob_id == blob_id) {
            return i;
        }
    }

    return -1;
}

static ssize_t drm_user_blob_generate_id_locked(uint32_t *blob_id) {
    uint32_t candidate = drm_user_blob_next_id;
    if (candidate <= DRM_BLOB_ID_USER_BASE ||
        candidate > DRM_BLOB_ID_USER_LAST) {
        candidate = DRM_BLOB_ID_USER_BASE + 1;
    }

    uint32_t id_space = DRM_BLOB_ID_USER_LAST - DRM_BLOB_ID_USER_BASE;
    for (uint32_t tries = 0; tries < id_space; tries++) {
        bool exists = false;
        for (int i = 0; i < DRM_MAX_USER_BLOBS; i++) {
            if (drm_user_blobs[i].used &&
                drm_user_blobs[i].blob_id == candidate) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            *blob_id = candidate;
            drm_user_blob_next_id = candidate + 1;
            if (drm_user_blob_next_id > DRM_BLOB_ID_USER_LAST) {
                drm_user_blob_next_id = DRM_BLOB_ID_USER_BASE + 1;
            }
            return 0;
        }

        candidate++;
        if (candidate > DRM_BLOB_ID_USER_LAST) {
            candidate = DRM_BLOB_ID_USER_BASE + 1;
        }
    }

    return -ENOSPC;
}

#define DRM_BLOB_ID_CRTC_MODE_BASE 0x10000000U
#define DRM_BLOB_ID_CONNECTOR_EDID_BASE 0x20000000U
#define DRM_BLOB_ID_PLANE_IN_FORMATS_BASE 0x28000000U

static uint32_t drm_crtc_mode_blob_id(uint32_t crtc_id) {
    return DRM_BLOB_ID_CRTC_MODE_BASE + crtc_id;
}

static uint32_t drm_connector_edid_blob_id(uint32_t connector_id) {
    return DRM_BLOB_ID_CONNECTOR_EDID_BASE + connector_id;
}

static uint32_t drm_plane_in_formats_blob_id(uint32_t plane_id) {
    return DRM_BLOB_ID_PLANE_IN_FORMATS_BASE + plane_id;
}

static bool drm_mode_blob_to_crtc_id(uint32_t blob_id, uint32_t *crtc_id) {
    if (blob_id <= DRM_BLOB_ID_CRTC_MODE_BASE ||
        blob_id >= DRM_BLOB_ID_CONNECTOR_EDID_BASE) {
        return false;
    }

    *crtc_id = blob_id - DRM_BLOB_ID_CRTC_MODE_BASE;
    return *crtc_id != 0;
}

static bool drm_blob_to_connector_edid_id(uint32_t blob_id,
                                          uint32_t *connector_id) {
    if (blob_id <= DRM_BLOB_ID_CONNECTOR_EDID_BASE ||
        blob_id >= DRM_BLOB_ID_PLANE_IN_FORMATS_BASE) {
        return false;
    }

    *connector_id = blob_id - DRM_BLOB_ID_CONNECTOR_EDID_BASE;
    return *connector_id != 0;
}

static bool drm_blob_to_plane_in_formats_id(uint32_t blob_id,
                                            uint32_t *plane_id) {
    if (blob_id <= DRM_BLOB_ID_PLANE_IN_FORMATS_BASE ||
        blob_id >= DRM_BLOB_ID_USER_BASE) {
        return false;
    }

    *plane_id = blob_id - DRM_BLOB_ID_PLANE_IN_FORMATS_BASE;
    return *plane_id != 0;
}

static void drm_fill_default_modeinfo(drm_device_t *dev,
                                      struct drm_mode_modeinfo *mode) {
    uint32_t width = 0, height = 0, bpp = 0;
    memset(mode, 0, sizeof(*mode));

    if (dev->op->get_display_info &&
        dev->op->get_display_info(dev, &width, &height, &bpp) == 0 &&
        width > 0 && height > 0) {
        mode->clock = width * HZ;
        mode->hdisplay = width;
        mode->hsync_start = width + 16;
        mode->hsync_end = width + 16 + 96;
        mode->htotal = width + 16 + 96 + 48;
        mode->vdisplay = height;
        mode->vsync_start = height + 10;
        mode->vsync_end = height + 10 + 2;
        mode->vtotal = height + 10 + 2 + 33;
        mode->vrefresh = HZ;
        sprintf(mode->name, "%dx%d", width, height);
        return;
    }

    strcpy(mode->name, "unknown");
}

static void drm_fill_crtc_modeinfo(drm_device_t *dev, drm_crtc_t *crtc,
                                   struct drm_mode_modeinfo *mode) {
    if (crtc && crtc->mode_valid && crtc->mode.hdisplay > 0 &&
        crtc->mode.vdisplay > 0) {
        memcpy(mode, &crtc->mode, sizeof(*mode));
        return;
    }

    drm_fill_default_modeinfo(dev, mode);
}

static void drm_edid_set_descriptor_text(uint8_t *desc, uint8_t tag,
                                         const char *text) {
    memset(desc, 0, 18);
    desc[3] = tag;
    desc[4] = 0x00;

    size_t i = 0;
    for (; i < 13 && text[i]; i++) {
        desc[5 + i] = (uint8_t)text[i];
    }
    if (i < 13) {
        desc[5 + i++] = '\n';
    }
    for (; i < 13; i++) {
        desc[5 + i] = ' ';
    }
}

static void drm_edid_fill_dtd(uint8_t *dtd, uint32_t width, uint32_t height,
                              uint32_t mm_width, uint32_t mm_height,
                              uint32_t refresh_hz) {
    uint32_t hblank = 160;
    uint32_t vblank = 45;
    uint32_t hsync_offset = 48;
    uint32_t hsync_pulse = 32;
    uint32_t vsync_offset = 3;
    uint32_t vsync_pulse = 5;
    uint32_t htotal = width + hblank;
    uint32_t vtotal = height + vblank;
    uint32_t pixel_clock_10khz = (htotal * vtotal * refresh_hz) / 10000U;

    memset(dtd, 0, 18);
    dtd[0] = pixel_clock_10khz & 0xff;
    dtd[1] = (pixel_clock_10khz >> 8) & 0xff;
    dtd[2] = width & 0xff;
    dtd[3] = hblank & 0xff;
    dtd[4] = ((width >> 8) & 0xf) << 4 | ((hblank >> 8) & 0xf);
    dtd[5] = height & 0xff;
    dtd[6] = vblank & 0xff;
    dtd[7] = ((height >> 8) & 0xf) << 4 | ((vblank >> 8) & 0xf);
    dtd[8] = hsync_offset & 0xff;
    dtd[9] = hsync_pulse & 0xff;
    dtd[10] = ((vsync_offset & 0xf) << 4) | (vsync_pulse & 0xf);
    dtd[11] = ((hsync_offset >> 8) & 0x3) << 6 |
              ((hsync_pulse >> 8) & 0x3) << 4 |
              ((vsync_offset >> 4) & 0x3) << 2 | ((vsync_pulse >> 4) & 0x3);
    dtd[12] = mm_width & 0xff;
    dtd[13] = mm_height & 0xff;
    dtd[14] = ((mm_width >> 8) & 0xf) << 4 | ((mm_height >> 8) & 0xf);
    dtd[17] = 0x1a;
}

static void drm_build_connector_edid(drm_device_t *dev, drm_connector_t *conn,
                                     uint8_t edid[128]) {
    uint32_t width = 1024;
    uint32_t height = 768;
    uint32_t refresh = 60;
    uint32_t mm_width = conn->mm_width;
    uint32_t mm_height = conn->mm_height;

    if (conn->modes && conn->count_modes > 0) {
        if (conn->modes[0].hdisplay > 0) {
            width = conn->modes[0].hdisplay;
        }
        if (conn->modes[0].vdisplay > 0) {
            height = conn->modes[0].vdisplay;
        }
        if (conn->modes[0].vrefresh > 0) {
            refresh = conn->modes[0].vrefresh;
        }
    } else if (dev->op->get_display_info) {
        uint32_t bpp = 0;
        if (dev->op->get_display_info(dev, &width, &height, &bpp) != 0) {
            width = 1024;
            height = 768;
        }
    }

    if (mm_width == 0) {
        mm_width = (width * 264U) / 1000U;
        if (mm_width == 0) {
            mm_width = 1;
        }
    }
    if (mm_height == 0) {
        mm_height = (height * 264U) / 1000U;
        if (mm_height == 0) {
            mm_height = 1;
        }
    }

    memset(edid, 0, 128);
    edid[0] = 0x00;
    edid[1] = 0xff;
    edid[2] = 0xff;
    edid[3] = 0xff;
    edid[4] = 0xff;
    edid[5] = 0xff;
    edid[6] = 0xff;
    edid[7] = 0x00;
    edid[8] = 0x38;
    edid[9] = 0x2f;
    edid[10] = 0x01;
    edid[11] = 0x00;
    edid[12] = 0x01;
    edid[13] = 0x00;
    edid[14] = 0x00;
    edid[15] = 0x00;
    edid[16] = 0x01;
    edid[17] = 34;
    edid[18] = 0x01;
    edid[19] = 0x04;
    edid[20] = 0x80;
    edid[21] = width & 0xff;
    edid[22] = height & 0xff;
    edid[23] = 0x78;
    edid[24] = 0x0a;

    for (int i = 38; i < 54; i++) {
        edid[i] = 0x01;
    }

    drm_edid_fill_dtd(&edid[54], width, height, mm_width, mm_height, refresh);
    drm_edid_set_descriptor_text(&edid[72], 0xfc, "NAOS Virtual");
    drm_edid_set_descriptor_text(&edid[90], 0xff, "00000001");
    drm_edid_set_descriptor_text(&edid[108], 0xfe, "NAOS DRM");

    edid[126] = 0;

    uint8_t sum = 0;
    for (int i = 0; i < 127; i++) {
        sum += edid[i];
    }
    edid[127] = (uint8_t)(0x100 - sum);
}

/**
 * drm_ioctl_version - Handle DRM_IOCTL_VERSION
 */
ssize_t drm_ioctl_version(drm_device_t *dev, void *arg) {
    struct drm_version *version = (struct drm_version *)arg;
    const char *name =
        (dev && dev->driver_name[0]) ? dev->driver_name : DRM_NAME;
    const char *date =
        (dev && dev->driver_date[0]) ? dev->driver_date : "20060810";
    const char *desc =
        (dev && dev->driver_desc[0]) ? dev->driver_desc : DRM_NAME;
    int version_major = 1;
    int version_minor = 0;
    int version_patchlevel = 0;

    if (!strcmp(name, "virtio_gpu")) {
        version_major = 0;
        version_minor = 1;
    }

    size_t user_name_len = version->name_len;
    size_t user_date_len = version->date_len;
    size_t user_desc_len = version->desc_len;

    version->version_major = version_major;
    version->version_minor = version_minor;
    version->version_patchlevel = version_patchlevel;
    version->name_len = strlen(name);
    if (version->name && user_name_len) {
        if (copy_to_user_str(version->name, name, user_name_len))
            return -EFAULT;
    }
    version->date_len = strlen(date);
    if (version->date && user_date_len) {
        if (copy_to_user_str(version->date, date, user_date_len))
            return -EFAULT;
    }
    version->desc_len = strlen(desc);
    if (version->desc && user_desc_len) {
        if (copy_to_user_str(version->desc, desc, user_desc_len))
            return -EFAULT;
    }
    return 0;
}

/**
 * drm_ioctl_get_cap - Handle DRM_IOCTL_GET_CAP
 */
ssize_t drm_ioctl_get_cap(drm_device_t *dev, void *arg) {
    struct drm_get_cap *cap = (struct drm_get_cap *)arg;
    switch (cap->capability) {
    case DRM_CAP_DUMB_BUFFER:
        cap->value = 1; // Support dumb buffer
        return 0;
    case DRM_CAP_DUMB_PREFERRED_DEPTH:
        cap->value = 24;
        return 0;
    case DRM_CAP_CRTC_IN_VBLANK_EVENT:
        cap->value = 1;
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
    case DRM_CAP_PRIME:
        cap->value = DRM_PRIME_CAP_EXPORT | DRM_PRIME_CAP_IMPORT;
        return 0;
    case DRM_CAP_ADDFB2_MODIFIERS:
        cap->value = 1;
        return 0;
    case DRM_CAP_DUMB_PREFER_SHADOW:
        cap->value = 0;
        return 0;
    case DRM_CAP_ATOMIC_ASYNC_PAGE_FLIP:
        cap->value = 1;
        return 0;
    default:
        printk("drm: Unsupported capability %d\n", cap->capability);
        cap->value = 0;
        return 0;
    }
}

/**
 * drm_ioctl_gem_close - Handle DRM_IOCTL_GEM_CLOSE
 */
ssize_t drm_ioctl_gem_close(drm_device_t *dev, void *arg) {
    struct drm_gem_close *close = (struct drm_gem_close *)arg;

    if (close->handle == 0) {
        return -EINVAL;
    }

    if (dev->op && dev->op->driver_ioctl) {
        ssize_t ret =
            dev->op->driver_ioctl(dev, DRM_IOCTL_GEM_CLOSE, arg, false);
        if (ret != -ENOTTY) {
            return ret;
        }
    }

    return 0;
}

/**
 * drm_ioctl_prime_handle_to_fd - Handle DRM_IOCTL_PRIME_HANDLE_TO_FD
 */
ssize_t drm_ioctl_prime_handle_to_fd(drm_device_t *dev, void *arg) {
    struct drm_prime_handle *prime = (struct drm_prime_handle *)arg;

    if (prime->flags & ~(DRM_CLOEXEC | DRM_RDWR)) {
        return -EINVAL;
    }

    uint64_t dumb_size = drm_dumb_get_size(dev, prime->handle);
    if (dumb_size == 0) {
        return -ENOENT;
    }

    uint64_t phys = 0;
    int ret = drm_prime_get_handle_phys(dev, prime->handle, &phys);
    if (ret) {
        return ret;
    }

    ssize_t fd_ret =
        drm_primefd_create(dev, prime->handle, phys, dumb_size, prime->flags);
    if (fd_ret < 0) {
        return fd_ret;
    }

    prime->fd = (int)fd_ret;
    return 0;
}

/**
 * drm_ioctl_prime_fd_to_handle - Handle DRM_IOCTL_PRIME_FD_TO_HANDLE
 */
ssize_t drm_ioctl_prime_fd_to_handle(drm_device_t *dev, void *arg) {
    struct drm_prime_handle *prime = (struct drm_prime_handle *)arg;

    if (prime->fd < 0 || prime->fd >= MAX_FD_NUM) {
        return -EBADF;
    }

    int direct_ret = -EBADF;
    with_fd_info_lock(current_task->fd_info, {
        fd_t *fd_obj = current_task->fd_info->fds[prime->fd];
        if (!fd_obj || !fd_obj->node || fd_obj->node->fsid != drm_prime_fsid ||
            !fd_obj->node->handle) {
            direct_ret = -EBADF;
        } else {
            drm_prime_fd_ctx_t *ctx = fd_obj->node->handle;
            if (ctx->dev != dev || ctx->handle == 0) {
                direct_ret = -EBADF;
            } else {
                prime->handle = ctx->handle;
                direct_ret = 0;
            }
        }
    });

    if (direct_ret == 0) {
        return 0;
    }

    uint64_t inode = 0;
    int ret = drm_prime_get_fd_inode(prime->fd, &inode);
    if (ret) {
        return ret;
    }

    uint32_t handle = 0;
    ret = drm_prime_lookup_handle(dev, inode, &handle);
    if (ret) {
        return ret;
    }

    prime->handle = handle;
    return 0;
}

/**
 * drm_ioctl_mode_getresources - Handle DRM_IOCTL_MODE_GETRESOURCES
 */
ssize_t drm_ioctl_mode_getresources(drm_device_t *dev, void *arg) {
    struct drm_mode_card_res *res = (struct drm_mode_card_res *)arg;
    uint32_t fbs_cap = res->count_fbs;
    uint32_t crtcs_cap = res->count_crtcs;
    uint32_t connectors_cap = res->count_connectors;
    uint32_t encoders_cap = res->count_encoders;

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
    if (res->encoder_id_ptr && encoders_cap > 0 && res->count_encoders > 0) {
        uint32_t copy_count = MIN(encoders_cap, res->count_encoders);
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_ENCODERS_PER_DEVICE; i++) {
            if (idx >= copy_count) {
                break;
            }
            if (dev->resource_mgr.encoders[i]) {
                uint32_t encoder_id = dev->resource_mgr.encoders[i]->id;
                int ret = drm_copy_to_user_ptr(res->encoder_id_ptr +
                                                   idx * sizeof(uint32_t),
                                               &encoder_id, sizeof(encoder_id));
                if (ret) {
                    return ret;
                }
                idx++;
            }
        }
    }

    // Fill CRTC IDs if pointer provided
    if (res->crtc_id_ptr && crtcs_cap > 0 && res->count_crtcs > 0) {
        uint32_t copy_count = MIN(crtcs_cap, res->count_crtcs);
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_CRTCS_PER_DEVICE; i++) {
            if (idx >= copy_count) {
                break;
            }
            if (dev->resource_mgr.crtcs[i]) {
                uint32_t crtc_id = dev->resource_mgr.crtcs[i]->id;
                int ret = drm_copy_to_user_ptr(res->crtc_id_ptr +
                                                   idx * sizeof(uint32_t),
                                               &crtc_id, sizeof(crtc_id));
                if (ret) {
                    return ret;
                }
                idx++;
            }
        }
    }

    // Fill connector IDs if pointer provided
    if (res->connector_id_ptr && connectors_cap > 0 &&
        res->count_connectors > 0) {
        uint32_t copy_count = MIN(connectors_cap, res->count_connectors);
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_CONNECTORS_PER_DEVICE; i++) {
            if (idx >= copy_count) {
                break;
            }
            if (dev->resource_mgr.connectors[i]) {
                uint32_t connector_id = dev->resource_mgr.connectors[i]->id;
                int ret = drm_copy_to_user_ptr(
                    res->connector_id_ptr + idx * sizeof(uint32_t),
                    &connector_id, sizeof(connector_id));
                if (ret) {
                    return ret;
                }
                idx++;
            }
        }
    }

    // Fill framebuffer IDs if pointer provided
    if (res->fb_id_ptr && fbs_cap > 0 && res->count_fbs > 0) {
        uint32_t copy_count = MIN(fbs_cap, res->count_fbs);
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; i++) {
            if (idx >= copy_count) {
                break;
            }
            if (dev->resource_mgr.framebuffers[i]) {
                uint32_t fb_id = dev->resource_mgr.framebuffers[i]->id;
                int ret = drm_copy_to_user_ptr(res->fb_id_ptr +
                                                   idx * sizeof(uint32_t),
                                               &fb_id, sizeof(fb_id));
                if (ret) {
                    return ret;
                }
                idx++;
            }
        }
    }

    return 0;
}

/**
 * drm_ioctl_mode_getcrtc - Handle DRM_IOCTL_MODE_GETCRTC
 */
ssize_t drm_ioctl_mode_getcrtc(drm_device_t *dev, void *arg) {
    struct drm_mode_crtc *crtc = (struct drm_mode_crtc *)arg;

    // Find the CRTC by ID
    drm_crtc_t *crtc_obj = drm_crtc_get(&dev->resource_mgr, crtc->crtc_id);
    if (!crtc_obj) {
        return -ENOENT;
    }

    struct drm_mode_modeinfo mode;
    drm_fill_crtc_modeinfo(dev, crtc_obj, &mode);

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
ssize_t drm_ioctl_mode_getencoder(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_mode_create_dumb(drm_device_t *dev, void *arg) {
    if (!dev->op->create_dumb) {
        return -ENOSYS;
    }
    struct drm_mode_create_dumb *create = (struct drm_mode_create_dumb *)arg;
    ssize_t ret = dev->op->create_dumb(dev, create);
    if (ret == 0) {
        drm_dumb_store_size(dev, create->handle, create->size);
    }
    return ret;
}

/**
 * drm_ioctl_mode_map_dumb - Handle DRM_IOCTL_MODE_MAP_DUMB
 */
ssize_t drm_ioctl_mode_map_dumb(drm_device_t *dev, void *arg) {
    if (!dev->op->map_dumb) {
        return -ENOSYS;
    }
    return dev->op->map_dumb(dev, (struct drm_mode_map_dumb *)arg);
}

/**
 * drm_ioctl_mode_destroy_dumb - Handle DRM_IOCTL_MODE_DESTROY_DUMB
 */
ssize_t drm_ioctl_mode_destroy_dumb(drm_device_t *dev, void *arg) {
    if (!dev->op->destroy_dumb) {
        return -ENOSYS;
    }

    struct drm_mode_destroy_dumb *destroy = (struct drm_mode_destroy_dumb *)arg;
    if (destroy->handle == 0) {
        return -EINVAL;
    }

    return dev->op->destroy_dumb(dev, destroy->handle);
}

/**
 * drm_ioctl_mode_getconnector - Handle DRM_IOCTL_MODE_GETCONNECTOR
 */
ssize_t drm_ioctl_mode_getconnector(drm_device_t *dev, void *arg) {
    struct drm_mode_get_connector *conn = (struct drm_mode_get_connector *)arg;
    uint32_t modes_cap = conn->count_modes;
    uint32_t props_cap = conn->count_props;
    uint32_t encoders_cap = conn->count_encoders;

    // Find the connector by ID
    drm_connector_t *connector =
        drm_connector_get(&dev->resource_mgr, conn->connector_id);
    if (!connector) {
        return -ENOENT;
    }

    uint32_t mode_width = 0;
    uint32_t mode_height = 0;
    if (connector->modes && connector->count_modes > 0) {
        mode_width = connector->modes[0].hdisplay;
        mode_height = connector->modes[0].vdisplay;
    } else if (dev->op->get_display_info) {
        uint32_t bpp = 0;
        if (dev->op->get_display_info(dev, &mode_width, &mode_height, &bpp) !=
            0) {
            mode_width = 0;
            mode_height = 0;
        }
    }

    conn->encoder_id = connector->encoder_id;
    conn->connector_type = connector->type;
    conn->connector_type_id = 1;
    conn->connection = connector->connection;
    conn->count_modes = connector->count_modes;
    conn->count_props = 3;
    conn->count_encoders = connector->encoder_id ? 1 : 0;
    conn->subpixel = connector->subpixel;
    conn->mm_width = connector->mm_width;
    conn->mm_height = connector->mm_height;
    if (conn->mm_width == 0 && mode_width > 0) {
        conn->mm_width = (mode_width * 264UL) / 1000UL;
        if (conn->mm_width == 0) {
            conn->mm_width = 1;
        }
    }
    if (conn->mm_height == 0 && mode_height > 0) {
        conn->mm_height = (mode_height * 264UL) / 1000UL;
        if (conn->mm_height == 0) {
            conn->mm_height = 1;
        }
    }

    // Fill modes if pointer provided
    if (conn->modes_ptr && connector->modes && connector->count_modes > 0) {
        uint32_t copy_modes = MIN(modes_cap, connector->count_modes);
        int ret =
            drm_copy_to_user_ptr(conn->modes_ptr, connector->modes,
                                 copy_modes * sizeof(struct drm_mode_modeinfo));
        if (ret) {
            drm_connector_free(&dev->resource_mgr, connector->id);
            return ret;
        }
    }

    // Fill encoders if pointer provided
    if (conn->encoders_ptr && conn->count_encoders > 0) {
        uint32_t copy_encoders = MIN(encoders_cap, conn->count_encoders);
        if (copy_encoders == 0) {
            goto skip_encoders;
        }
        int ret =
            drm_copy_to_user_ptr(conn->encoders_ptr, &connector->encoder_id,
                                 sizeof(connector->encoder_id));
        if (ret) {
            drm_connector_free(&dev->resource_mgr, connector->id);
            return ret;
        }
    }
skip_encoders:

    // Fill properties if pointers provided
    if (conn->count_props > 0) {
        uint32_t prop_ids[3] = {DRM_CONNECTOR_DPMS_PROP_ID,
                                DRM_CONNECTOR_EDID_PROP_ID,
                                DRM_CONNECTOR_CRTC_ID_PROP_ID};
        uint64_t prop_values[3] = {DRM_MODE_DPMS_ON, 0, connector->crtc_id};
        prop_values[1] = drm_connector_edid_blob_id(connector->id);
        uint32_t copy_props = MIN(props_cap, conn->count_props);

        if (conn->props_ptr && copy_props > 0) {
            int ret = drm_copy_to_user_ptr(conn->props_ptr, prop_ids,
                                           copy_props * sizeof(uint32_t));
            if (ret) {
                drm_connector_free(&dev->resource_mgr, connector->id);
                return ret;
            }
        }

        if (conn->prop_values_ptr && copy_props > 0) {
            int ret = drm_copy_to_user_ptr(conn->prop_values_ptr, prop_values,
                                           copy_props * sizeof(uint64_t));
            if (ret) {
                drm_connector_free(&dev->resource_mgr, connector->id);
                return ret;
            }
        }
    }

    // Release reference
    drm_connector_free(&dev->resource_mgr, connector->id);
    return 0;
}

/**
 * drm_ioctl_mode_getfb - Handle DRM_IOCTL_MODE_GETFB
 */
ssize_t drm_ioctl_mode_getfb(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_mode_addfb(drm_device_t *dev, void *arg) {
    if (!dev->op->add_fb) {
        return -ENOSYS;
    }
    return dev->op->add_fb(dev, (struct drm_mode_fb_cmd *)arg);
}

/**
 * drm_ioctl_mode_addfb2 - Handle DRM_IOCTL_MODE_ADDFB2
 */
ssize_t drm_ioctl_mode_addfb2(drm_device_t *dev, void *arg) {
    if (!dev->op->add_fb2) {
        return -ENOSYS;
    }
    return dev->op->add_fb2(dev, (struct drm_mode_fb_cmd2 *)arg);
}

/**
 * drm_ioctl_mode_setcrtc - Handle DRM_IOCTL_MODE_SETCRTC
 */
ssize_t drm_ioctl_mode_setcrtc(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_mode_getplaneresources(drm_device_t *dev, void *arg) {
    struct drm_mode_get_plane_res *res = (struct drm_mode_get_plane_res *)arg;
    uint32_t planes_cap = res->count_planes;

    // Count available planes
    res->count_planes = 0;
    for (uint32_t i = 0; i < DRM_MAX_PLANES_PER_DEVICE; i++) {
        if (dev->resource_mgr.planes[i]) {
            res->count_planes++;
        }
    }

    // Fill plane IDs if pointer provided
    if (res->plane_id_ptr && planes_cap > 0 && res->count_planes > 0) {
        uint32_t copy_count = MIN(planes_cap, res->count_planes);
        uint32_t idx = 0;
        for (uint32_t i = 0; i < DRM_MAX_PLANES_PER_DEVICE; i++) {
            if (idx >= copy_count) {
                break;
            }
            if (dev->resource_mgr.planes[i]) {
                uint32_t plane_id = dev->resource_mgr.planes[i]->id;
                int ret = drm_copy_to_user_ptr(res->plane_id_ptr +
                                                   idx * sizeof(uint32_t),
                                               &plane_id, sizeof(plane_id));
                if (ret) {
                    return ret;
                }
                idx++;
            }
        }
    }

    return 0;
}

/**
 * drm_ioctl_mode_getplane - Handle DRM_IOCTL_MODE_GETPLANE
 */
ssize_t drm_ioctl_mode_getplane(drm_device_t *dev, void *arg) {
    struct drm_mode_get_plane *plane_cmd = (struct drm_mode_get_plane *)arg;
    uint32_t format_cap = plane_cmd->count_format_types;

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
    if (plane_cmd->format_type_ptr && format_cap > 0 &&
        plane->count_format_types > 0 && plane->format_types) {
        uint32_t copy_count = MIN(format_cap, plane->count_format_types);
        int ret = drm_copy_to_user_ptr(plane_cmd->format_type_ptr,
                                       plane->format_types,
                                       copy_count * sizeof(uint32_t));
        if (ret) {
            drm_plane_free(&dev->resource_mgr, plane->id);
            return ret;
        }
    }

    // Release reference
    drm_plane_free(&dev->resource_mgr, plane->id);
    return 0;
}

/**
 * drm_ioctl_mode_setplane - Handle DRM_IOCTL_MODE_SETPLANE
 */
ssize_t drm_ioctl_mode_setplane(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_mode_getproperty(drm_device_t *dev, void *arg) {
    struct drm_mode_get_property *prop = (struct drm_mode_get_property *)arg;
    uint32_t values_cap = prop->count_values;
    uint32_t enum_blobs_cap = prop->count_enum_blobs;

    switch (prop->prop_id) {
    case DRM_PROPERTY_ID_FB_ID:
        prop->flags = DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "FB_ID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 1;
        if (prop->values_ptr) {
            uint64_t values[1] = {DRM_MODE_OBJECT_FB};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_PROPERTY_ID_CRTC_ID:
    case DRM_CONNECTOR_CRTC_ID_PROP_ID:
        prop->flags = DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "CRTC_ID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 1;
        if (prop->values_ptr) {
            uint64_t values[1] = {DRM_MODE_OBJECT_CRTC};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_PROPERTY_ID_CRTC_X:
    case DRM_PROPERTY_ID_CRTC_Y:
        prop->flags = DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC;
        if (prop->prop_id == DRM_PROPERTY_ID_CRTC_X)
            strncpy((char *)prop->name, "CRTC_X", DRM_PROP_NAME_LEN);
        else
            strncpy((char *)prop->name, "CRTC_Y", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t values[2] = {(uint64_t)(-(1LL << 31)),
                                  (uint64_t)((1LL << 31) - 1)};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_PROPERTY_ID_SRC_X:
    case DRM_PROPERTY_ID_SRC_Y:
    case DRM_PROPERTY_ID_SRC_W:
    case DRM_PROPERTY_ID_SRC_H:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        if (prop->prop_id == DRM_PROPERTY_ID_SRC_X) {
            strncpy((char *)prop->name, "SRC_X", DRM_PROP_NAME_LEN);
        } else if (prop->prop_id == DRM_PROPERTY_ID_SRC_Y) {
            strncpy((char *)prop->name, "SRC_Y", DRM_PROP_NAME_LEN);
        } else if (prop->prop_id == DRM_PROPERTY_ID_SRC_W) {
            strncpy((char *)prop->name, "SRC_W", DRM_PROP_NAME_LEN);
        } else {
            strncpy((char *)prop->name, "SRC_H", DRM_PROP_NAME_LEN);
        }
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t values[2] = {0, UINT32_MAX};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_PROPERTY_ID_CRTC_W:
    case DRM_PROPERTY_ID_CRTC_H:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        if (prop->prop_id == DRM_PROPERTY_ID_CRTC_W)
            strncpy((char *)prop->name, "CRTC_W", DRM_PROP_NAME_LEN);
        else
            strncpy((char *)prop->name, "CRTC_H", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t values[2] = {0, 8192};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_PROPERTY_ID_PLANE_TYPE:
        prop->flags = DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE;
        strncpy((char *)prop->name, "type", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 3;
        if (prop->enum_blob_ptr) {
            struct drm_mode_property_enum enums[3];
            memset(enums, 0, sizeof(enums));

            strncpy(enums[0].name, "Primary", DRM_PROP_NAME_LEN);
            enums[0].value = DRM_PLANE_TYPE_PRIMARY;
            strncpy(enums[1].name, "Overlay", DRM_PROP_NAME_LEN);
            enums[1].value = DRM_PLANE_TYPE_OVERLAY;
            strncpy(enums[2].name, "Cursor", DRM_PROP_NAME_LEN);
            enums[2].value = DRM_PLANE_TYPE_CURSOR;

            uint32_t copy_enums = MIN(enum_blobs_cap, prop->count_enum_blobs);
            int ret = drm_copy_to_user_ptr(
                prop->enum_blob_ptr, enums,
                copy_enums * sizeof(struct drm_mode_property_enum));
            if (ret) {
                return ret;
            }
        }
        prop->count_values = 0;
        return 0;

    case DRM_CRTC_MODE_ID_PROP_ID:
        prop->flags = DRM_MODE_PROP_BLOB | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "MODE_ID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 0;
        return 0;

    case DRM_CRTC_ACTIVE_PROP_ID:
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        strncpy((char *)prop->name, "ACTIVE", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t values[2] = {0, 1};
            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;

    case DRM_FB_WIDTH_PROP_ID:
    case DRM_FB_HEIGHT_PROP_ID:
    case DRM_FB_BPP_PROP_ID:
    case DRM_FB_DEPTH_PROP_ID: {
        prop->flags = DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC;
        if (prop->prop_id == DRM_FB_WIDTH_PROP_ID)
            strncpy((char *)prop->name, "WIDTH", DRM_PROP_NAME_LEN);
        else if (prop->prop_id == DRM_FB_HEIGHT_PROP_ID)
            strncpy((char *)prop->name, "HEIGHT", DRM_PROP_NAME_LEN);
        else if (prop->prop_id == DRM_FB_BPP_PROP_ID)
            strncpy((char *)prop->name, "BPP", DRM_PROP_NAME_LEN);
        else
            strncpy((char *)prop->name, "DEPTH", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 2;
        if (prop->values_ptr) {
            uint64_t values[2];
            if (prop->prop_id == DRM_FB_BPP_PROP_ID ||
                prop->prop_id == DRM_FB_DEPTH_PROP_ID) {
                values[0] = 8;
                values[1] = 32;
            } else {
                values[0] = 1;
                values[1] = 8192;
            }

            uint32_t copy_values = MIN(values_cap, prop->count_values);
            int ret = drm_copy_to_user_ptr(prop->values_ptr, values,
                                           copy_values * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        return 0;
    }

    case DRM_CONNECTOR_DPMS_PROP_ID:
        prop->flags = DRM_MODE_PROP_ENUM;
        strncpy((char *)prop->name, "DPMS", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 4;
        if (prop->enum_blob_ptr) {
            struct drm_mode_property_enum enums[4];
            memset(enums, 0, sizeof(enums));

            strncpy(enums[0].name, "On", DRM_PROP_NAME_LEN);
            enums[0].value = DRM_MODE_DPMS_ON;
            strncpy(enums[1].name, "Standby", DRM_PROP_NAME_LEN);
            enums[1].value = DRM_MODE_DPMS_STANDBY;
            strncpy(enums[2].name, "Suspend", DRM_PROP_NAME_LEN);
            enums[2].value = DRM_MODE_DPMS_SUSPEND;
            strncpy(enums[3].name, "Off", DRM_PROP_NAME_LEN);
            enums[3].value = DRM_MODE_DPMS_OFF;

            uint32_t copy_enums = MIN(enum_blobs_cap, prop->count_enum_blobs);
            int ret = drm_copy_to_user_ptr(
                prop->enum_blob_ptr, enums,
                copy_enums * sizeof(struct drm_mode_property_enum));
            if (ret) {
                return ret;
            }
        }
        prop->count_values = 0;
        return 0;

    case DRM_CONNECTOR_EDID_PROP_ID:
        prop->flags = DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE;
        strncpy((char *)prop->name, "EDID", DRM_PROP_NAME_LEN);
        prop->name[DRM_PROP_NAME_LEN - 1] = '\0';
        prop->count_enum_blobs = 0;
        prop->count_values = 0;
        return 0;

    case DRM_PROPERTY_ID_IN_FORMATS:
        prop->flags = DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE;
        strncpy((char *)prop->name, "IN_FORMATS", DRM_PROP_NAME_LEN);
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
 * drm_ioctl_mode_createpropblob - Handle DRM_IOCTL_MODE_CREATEPROPBLOB
 */
ssize_t drm_ioctl_mode_createpropblob(drm_device_t *dev, void *arg) {
    struct drm_mode_create_blob *create_blob =
        (struct drm_mode_create_blob *)arg;

    if (!create_blob->data || create_blob->length == 0 ||
        create_blob->length > DRM_USER_BLOB_MAX_SIZE) {
        return -EINVAL;
    }

    void *blob_data = malloc(create_blob->length);
    if (!blob_data) {
        return -ENOMEM;
    }

    if (copy_from_user(blob_data, (void *)(uintptr_t)create_blob->data,
                       create_blob->length)) {
        free(blob_data);
        return -EFAULT;
    }

    int free_slot = -1;
    uint32_t blob_id = 0;

    spin_lock(&drm_user_blobs_lock);
    for (int i = 0; i < DRM_MAX_USER_BLOBS; i++) {
        if (!drm_user_blobs[i].used) {
            free_slot = i;
            break;
        }
    }

    if (free_slot < 0) {
        spin_unlock(&drm_user_blobs_lock);
        free(blob_data);
        return -ENOSPC;
    }

    int ret = drm_user_blob_generate_id_locked(&blob_id);
    if (ret) {
        spin_unlock(&drm_user_blobs_lock);
        free(blob_data);
        return ret;
    }

    drm_user_blobs[free_slot].used = true;
    drm_user_blobs[free_slot].dev = dev;
    drm_user_blobs[free_slot].blob_id = blob_id;
    drm_user_blobs[free_slot].length = create_blob->length;
    drm_user_blobs[free_slot].data = blob_data;
    spin_unlock(&drm_user_blobs_lock);

    create_blob->blob_id = blob_id;
    return 0;
}

/**
 * drm_ioctl_mode_destroypropblob - Handle DRM_IOCTL_MODE_DESTROYPROPBLOB
 */
ssize_t drm_ioctl_mode_destroypropblob(drm_device_t *dev, void *arg) {
    struct drm_mode_destroy_blob *destroy_blob =
        (struct drm_mode_destroy_blob *)arg;

    if (destroy_blob->blob_id == 0) {
        return -EINVAL;
    }

    int idx = -1;
    void *blob_data = NULL;

    spin_lock(&drm_user_blobs_lock);
    idx = drm_user_blob_find_index_locked(dev, destroy_blob->blob_id);
    if (idx >= 0) {
        blob_data = drm_user_blobs[idx].data;
        memset(&drm_user_blobs[idx], 0, sizeof(drm_user_blobs[idx]));
        spin_unlock(&drm_user_blobs_lock);

        free(blob_data);
        return 0;
    }
    spin_unlock(&drm_user_blobs_lock);

    uint32_t reserved_obj_id = 0;
    if (destroy_blob->blob_id == DRM_BLOB_ID_PLANE_TYPE ||
        drm_mode_blob_to_crtc_id(destroy_blob->blob_id, &reserved_obj_id) ||
        drm_blob_to_plane_in_formats_id(destroy_blob->blob_id,
                                        &reserved_obj_id) ||
        drm_blob_to_connector_edid_id(destroy_blob->blob_id,
                                      &reserved_obj_id)) {
        return -EPERM;
    }

    return -ENOENT;
}

/**
 * drm_ioctl_mode_getpropblob - Handle DRM_IOCTL_MODE_GETPROPBLOB
 */
ssize_t drm_ioctl_mode_getpropblob(drm_device_t *dev, void *arg) {
    struct drm_mode_get_blob *blob = (struct drm_mode_get_blob *)arg;

    uint32_t crtc_id = 0;
    if (drm_mode_blob_to_crtc_id(blob->blob_id, &crtc_id)) {
        drm_crtc_t *crtc = drm_crtc_get(&dev->resource_mgr, crtc_id);
        if (!crtc) {
            return -ENOENT;
        }

        struct drm_mode_modeinfo mode;
        drm_fill_crtc_modeinfo(dev, crtc, &mode);
        drm_crtc_free(&dev->resource_mgr, crtc->id);

        size_t blob_len = sizeof(mode);
        size_t copy_len = MIN((size_t)blob->length, blob_len);

        blob->length = (uint32_t)blob_len;
        if (copy_len > 0 && blob->data) {
            int ret = drm_copy_to_user_ptr(blob->data, &mode, copy_len);
            if (ret) {
                return ret;
            }
        }
        return 0;
    }

    uint32_t connector_id = 0;
    if (drm_blob_to_connector_edid_id(blob->blob_id, &connector_id)) {
        drm_connector_t *connector =
            drm_connector_get(&dev->resource_mgr, connector_id);
        if (!connector) {
            return -ENOENT;
        }

        uint8_t edid[128];
        drm_build_connector_edid(dev, connector, edid);
        drm_connector_free(&dev->resource_mgr, connector->id);

        size_t blob_len = sizeof(edid);
        size_t copy_len = MIN((size_t)blob->length, blob_len);
        blob->length = (uint32_t)blob_len;

        if (copy_len > 0 && blob->data) {
            int ret = drm_copy_to_user_ptr(blob->data, edid, copy_len);
            if (ret) {
                return ret;
            }
        }
        return 0;
    }

    uint32_t plane_id = 0;
    if (drm_blob_to_plane_in_formats_id(blob->blob_id, &plane_id)) {
        drm_plane_t *plane = drm_plane_get(&dev->resource_mgr, plane_id);
        if (!plane) {
            return -ENOENT;
        }

        if (plane->count_format_types == 0 || !plane->format_types) {
            drm_plane_free(&dev->resource_mgr, plane->id);
            return -ENOENT;
        }

        uint32_t count_formats = plane->count_format_types;
        uint32_t count_modifiers = (count_formats + 63U) / 64U;
        size_t formats_len = (size_t)count_formats * sizeof(uint32_t);
        size_t modifiers_len =
            (size_t)count_modifiers * sizeof(struct drm_format_modifier);
        size_t blob_len = sizeof(struct drm_format_modifier_blob) + formats_len +
                          modifiers_len;

        uint8_t *blob_data = malloc(blob_len);
        if (!blob_data) {
            drm_plane_free(&dev->resource_mgr, plane->id);
            return -ENOMEM;
        }

        struct drm_format_modifier_blob *fmt_blob =
            (struct drm_format_modifier_blob *)blob_data;
        memset(fmt_blob, 0, sizeof(*fmt_blob));
        fmt_blob->version = FORMAT_BLOB_CURRENT;
        fmt_blob->count_formats = count_formats;
        fmt_blob->formats_offset = sizeof(struct drm_format_modifier_blob);
        fmt_blob->count_modifiers = count_modifiers;
        fmt_blob->modifiers_offset = fmt_blob->formats_offset + formats_len;

        uint32_t *formats = (uint32_t *)(blob_data + fmt_blob->formats_offset);
        memcpy(formats, plane->format_types, formats_len);

        struct drm_format_modifier *mods =
            (struct drm_format_modifier *)(blob_data +
                                           fmt_blob->modifiers_offset);
        for (uint32_t chunk = 0; chunk < count_modifiers; chunk++) {
            uint32_t offset = chunk * 64U;
            uint32_t remain = count_formats - offset;
            uint32_t bits = MIN(remain, 64U);

            mods[chunk].offset = offset;
            mods[chunk].pad = 0;
            mods[chunk].modifier = 0;
            mods[chunk].formats =
                (bits == 64U) ? UINT64_MAX : ((1ULL << bits) - 1ULL);
        }

        drm_plane_free(&dev->resource_mgr, plane->id);

        size_t copy_len = MIN((size_t)blob->length, blob_len);
        blob->length = (uint32_t)blob_len;
        int ret = 0;
        if (copy_len > 0 && blob->data) {
            ret = drm_copy_to_user_ptr(blob->data, blob_data, copy_len);
        }
        free(blob_data);
        return ret;
    }

    spin_lock(&drm_user_blobs_lock);
    int idx = drm_user_blob_find_index_locked(dev, blob->blob_id);
    if (idx >= 0) {
        size_t blob_len = drm_user_blobs[idx].length;
        size_t copy_len = MIN((size_t)blob->length, blob_len);
        blob->length = (uint32_t)blob_len;

        int ret = 0;
        if (copy_len > 0 && blob->data) {
            ret = drm_copy_to_user_ptr(blob->data, drm_user_blobs[idx].data,
                                       copy_len);
        }
        spin_unlock(&drm_user_blobs_lock);
        return ret;
    }
    spin_unlock(&drm_user_blobs_lock);

    switch (blob->blob_id) {
    case DRM_BLOB_ID_PLANE_TYPE: {
        static const char plane_type_blob[] = "Primary";
        size_t blob_len = sizeof(plane_type_blob) - 1;
        size_t copy_len = MIN((size_t)blob->length, blob_len);

        blob->length = (uint32_t)blob_len;
        if (copy_len > 0 && blob->data) {
            int ret =
                drm_copy_to_user_ptr(blob->data, plane_type_blob, copy_len);
            if (ret) {
                return ret;
            }
        }
        break;
    }

    default:
        printk("drm: Invalid blob id %d\n", blob->blob_id);
        return -ENOENT;
    }

    return 0;
}

static ssize_t drm_mode_resolve_obj_type(drm_device_t *dev, uint32_t obj_id,
                                         uint32_t *obj_type) {
    uint32_t resolved_type = DRM_MODE_OBJECT_ANY;

    for (int idx = 0; idx < DRM_MAX_CONNECTORS_PER_DEVICE; idx++) {
        if (!dev->resource_mgr.connectors[idx] ||
            dev->resource_mgr.connectors[idx]->id != obj_id) {
            continue;
        }

        resolved_type = DRM_MODE_OBJECT_CONNECTOR;
        break;
    }

    for (int idx = 0; idx < DRM_MAX_CRTCS_PER_DEVICE; idx++) {
        if (!dev->resource_mgr.crtcs[idx] ||
            dev->resource_mgr.crtcs[idx]->id != obj_id) {
            continue;
        }

        if (resolved_type != DRM_MODE_OBJECT_ANY &&
            resolved_type != DRM_MODE_OBJECT_CRTC) {
            return -EINVAL;
        }
        resolved_type = DRM_MODE_OBJECT_CRTC;
        break;
    }

    for (int idx = 0; idx < DRM_MAX_ENCODERS_PER_DEVICE; idx++) {
        if (!dev->resource_mgr.encoders[idx] ||
            dev->resource_mgr.encoders[idx]->id != obj_id) {
            continue;
        }

        if (resolved_type != DRM_MODE_OBJECT_ANY &&
            resolved_type != DRM_MODE_OBJECT_ENCODER) {
            return -EINVAL;
        }
        resolved_type = DRM_MODE_OBJECT_ENCODER;
        break;
    }

    for (int idx = 0; idx < DRM_MAX_FRAMEBUFFERS_PER_DEVICE; idx++) {
        if (!dev->resource_mgr.framebuffers[idx] ||
            dev->resource_mgr.framebuffers[idx]->id != obj_id) {
            continue;
        }

        if (resolved_type != DRM_MODE_OBJECT_ANY &&
            resolved_type != DRM_MODE_OBJECT_FB) {
            return -EINVAL;
        }
        resolved_type = DRM_MODE_OBJECT_FB;
        break;
    }

    for (int idx = 0; idx < DRM_MAX_PLANES_PER_DEVICE; idx++) {
        if (!dev->resource_mgr.planes[idx] ||
            dev->resource_mgr.planes[idx]->id != obj_id) {
            continue;
        }

        if (resolved_type != DRM_MODE_OBJECT_ANY &&
            resolved_type != DRM_MODE_OBJECT_PLANE) {
            return -EINVAL;
        }
        resolved_type = DRM_MODE_OBJECT_PLANE;
        break;
    }

    if (resolved_type == DRM_MODE_OBJECT_ANY) {
        return -ENOENT;
    }

    *obj_type = resolved_type;
    return 0;
}

/**
 * drm_ioctl_mode_obj_getproperties - Handle DRM_IOCTL_MODE_OBJ_GETPROPERTIES
 */
ssize_t drm_ioctl_mode_obj_getproperties(drm_device_t *dev, void *arg) {
    struct drm_mode_obj_get_properties *props =
        (struct drm_mode_obj_get_properties *)arg;
    uint32_t obj_type = props->obj_type;
    uint32_t props_cap = props->count_props;

    if (obj_type == DRM_MODE_OBJECT_ANY) {
        int ret = drm_mode_resolve_obj_type(dev, props->obj_id, &obj_type);
        if (ret == -ENOENT) {
            printk("drm: Unknown object ID: %u\n", props->obj_id);
        } else if (ret == -EINVAL) {
            printk("drm: Ambiguous object ID: %u\n", props->obj_id);
        }
        if (ret) {
            return ret;
        }
    }

    switch (obj_type) {
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

        // Plane properties needed by wlroots/smithay/weston style atomic userspace.
        props->count_props = 12;

        if (props->props_ptr) {
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint32_t prop_ids[12] = {
                DRM_PROPERTY_ID_PLANE_TYPE,  DRM_PROPERTY_ID_IN_FORMATS,
                DRM_PROPERTY_ID_FB_ID,       DRM_PROPERTY_ID_CRTC_ID,
                DRM_PROPERTY_ID_SRC_X,       DRM_PROPERTY_ID_SRC_Y,
                DRM_PROPERTY_ID_SRC_W,       DRM_PROPERTY_ID_SRC_H,
                DRM_PROPERTY_ID_CRTC_X,      DRM_PROPERTY_ID_CRTC_Y,
                DRM_PROPERTY_ID_CRTC_W,      DRM_PROPERTY_ID_CRTC_H,
            };

            int ret = drm_copy_to_user_ptr(props->props_ptr, prop_ids,
                                           copy_props * sizeof(uint32_t));
            if (ret) {
                return ret;
            }
        }
        if (props->prop_values_ptr) {
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint64_t prop_values[12];

            prop_values[0] = plane->plane_type;
            prop_values[1] = drm_plane_in_formats_blob_id(plane->id);
            prop_values[2] = plane->fb_id; // 当前关联的 framebuffer
            prop_values[3] = plane->crtc_id;
            prop_values[4] = 0;
            prop_values[5] = 0;
            prop_values[6] = 0;
            prop_values[7] = 0;

            drm_crtc_t *crtc = NULL;
            if (plane->crtc_id) {
                crtc = drm_crtc_get(&dev->resource_mgr, plane->crtc_id);
            }

            drm_framebuffer_t *fb = NULL;
            if (plane->fb_id) {
                fb = drm_framebuffer_get(&dev->resource_mgr, plane->fb_id);
            }

            if (fb) {
                prop_values[6] = ((uint64_t)fb->width) << 16;
                prop_values[7] = ((uint64_t)fb->height) << 16;
                drm_framebuffer_free(&dev->resource_mgr, fb->id);
            } else if (crtc) {
                prop_values[6] = ((uint64_t)crtc->w) << 16;
                prop_values[7] = ((uint64_t)crtc->h) << 16;
            }

            if (crtc) {
                prop_values[8] = crtc->x;
                prop_values[9] = crtc->y;
                prop_values[10] = crtc->w;
                prop_values[11] = crtc->h;
                drm_crtc_free(&dev->resource_mgr, crtc->id);
            } else {
                prop_values[8] = 0;
                prop_values[9] = 0;
                prop_values[10] = 0;
                prop_values[11] = 0;
            }

            int ret = drm_copy_to_user_ptr(props->prop_values_ptr, prop_values,
                                           copy_props * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
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
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint32_t prop_ids[2] = {DRM_CRTC_ACTIVE_PROP_ID,
                                    DRM_CRTC_MODE_ID_PROP_ID};
            int ret = drm_copy_to_user_ptr(props->props_ptr, prop_ids,
                                           copy_props * sizeof(uint32_t));
            if (ret) {
                return ret;
            }
        }
        if (props->prop_values_ptr) {
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint64_t prop_values[2] = {1, drm_crtc_mode_blob_id(crtc->id)};
            int ret = drm_copy_to_user_ptr(props->prop_values_ptr, prop_values,
                                           copy_props * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
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
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint32_t prop_ids[4] = {DRM_FB_WIDTH_PROP_ID, DRM_FB_HEIGHT_PROP_ID,
                                    DRM_FB_BPP_PROP_ID, DRM_FB_DEPTH_PROP_ID};
            int ret = drm_copy_to_user_ptr(props->props_ptr, prop_ids,
                                           copy_props * sizeof(uint32_t));
            if (ret) {
                return ret;
            }
        }
        if (props->prop_values_ptr) {
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint64_t prop_values[4] = {fb->width, fb->height, fb->bpp,
                                       fb->depth};
            int ret = drm_copy_to_user_ptr(props->prop_values_ptr, prop_values,
                                           copy_props * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
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
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint32_t prop_ids[3] = {DRM_CONNECTOR_DPMS_PROP_ID,
                                    DRM_CONNECTOR_EDID_PROP_ID,
                                    DRM_CONNECTOR_CRTC_ID_PROP_ID};
            int ret = drm_copy_to_user_ptr(props->props_ptr, prop_ids,
                                           copy_props * sizeof(uint32_t));
            if (ret) {
                return ret;
            }
        }
        if (props->prop_values_ptr) {
            uint32_t copy_props = MIN(props_cap, props->count_props);
            uint64_t prop_values[3] = {DRM_MODE_DPMS_ON, 0, connector->crtc_id};
            prop_values[1] = drm_connector_edid_blob_id(connector->id);
            int ret = drm_copy_to_user_ptr(props->prop_values_ptr, prop_values,
                                           copy_props * sizeof(uint64_t));
            if (ret) {
                return ret;
            }
        }
        break;
    }

    case DRM_MODE_OBJECT_ENCODER: {
        drm_encoder_t *encoder = NULL;
        for (int idx = 0; idx < DRM_MAX_ENCODERS_PER_DEVICE; idx++) {
            if (dev->resource_mgr.encoders[idx] &&
                dev->resource_mgr.encoders[idx]->id == props->obj_id) {
                encoder = dev->resource_mgr.encoders[idx];
                break;
            }
        }

        if (!encoder) {
            return -ENOENT;
        }

        props->count_props = 0;
        break;
    }

    default:
        printk("drm: Unsupported object type: %u\n", obj_type);
        return -EINVAL;
    }

    return 0;
}

/**
 * drm_ioctl_set_client_cap - Handle DRM_IOCTL_SET_CLIENT_CAP
 */
ssize_t drm_ioctl_set_client_cap(drm_device_t *dev, void *arg) {
    struct drm_set_client_cap *cap = (struct drm_set_client_cap *)arg;
    switch (cap->capability) {
    case DRM_CLIENT_CAP_ATOMIC:
        return 0;
    case DRM_CLIENT_CAP_UNIVERSAL_PLANES:
        return 0;
    case DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT:
        return 0;
    case DRM_CLIENT_CAP_WRITEBACK_CONNECTORS:
        return 0;
    default:
        printk("drm: Invalid client capability %d\n", cap->capability);
        return -EINVAL;
    }
}

/**
 * drm_ioctl_wait_vblank - Handle DRM_IOCTL_WAIT_VBLANK
 */
ssize_t drm_ioctl_wait_vblank(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_get_unique(drm_device_t *dev, void *arg) {
    struct drm_unique *u = (struct drm_unique *)arg;
    (void)dev;

    if (u->unique &&
        copy_to_user_str((char *)(uintptr_t)u->unique, "pci:0000:00:00.0",
                         u->unique_len ? u->unique_len : 1)) {
        return -EFAULT;
    }
    u->unique_len = 17;

    return 0;
}

/**
 * drm_ioctl_page_flip - Handle DRM_IOCTL_MODE_PAGE_FLIP
 */
ssize_t drm_ioctl_page_flip(drm_device_t *dev, void *arg) {
    if (!dev->op->page_flip) {
        return -ENOSYS;
    }
    return dev->op->page_flip(dev, (struct drm_mode_crtc_page_flip *)arg);
}

/**
 * drm_ioctl_cursor - Handle DRM_IOCTL_MODE_CURSOR
 */
ssize_t drm_ioctl_cursor(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_cursor2(drm_device_t *dev, void *arg) {
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
ssize_t drm_ioctl_atomic(drm_device_t *dev, void *arg) {
    struct drm_mode_atomic *cmd = (struct drm_mode_atomic *)arg;
    if (cmd->flags & DRM_MODE_ATOMIC_TEST_ONLY) {
        return 0;
    } else if (cmd->flags & DRM_MODE_CURSOR_MOVE) {
        return 0;
    } else {
        if (dev->op->atomic_commit)
            return dev->op->atomic_commit(dev, cmd);
    }

    return 0;
}

/**
 * drm_ioctl_get_magic - Handle DRM_IOCTL_GET_MAGIC
 */
ssize_t drm_ioctl_get_magic(drm_device_t *dev, void *arg) {
    drm_auth_t *auth = (drm_auth_t *)arg;
    (void)dev;

    auth->magic = 0x12345678;
    return 0;
}

/**
 * drm_ioctl_auth_magic - Handle DRM_IOCTL_AUTH_MAGIC
 */
ssize_t drm_ioctl_auth_magic(drm_device_t *dev, void *arg) {
    drm_auth_t *auth = (drm_auth_t *)arg;
    if (auth->magic != 0x12345678)
        return -EINVAL;

    return 0;
}

/**
 * drm_ioctl_set_master - Handle DRM_IOCTL_SET_MASTER
 */
ssize_t drm_ioctl_set_master(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_drop_master - Handle DRM_IOCTL_DROP_MASTER
 */
ssize_t drm_ioctl_drop_master(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_gamma - Handle DRM_IOCTL_MODE_GETGAMMA/DRM_IOCTL_MODE_SETGAMMA
 */
ssize_t drm_ioctl_gamma(drm_device_t *dev, void *arg, ssize_t cmd) {
    (void)dev;
    (void)arg;
    (void)cmd;
    return 0;
}

/**
 * drm_ioctl_dirtyfb - Handle DRM_IOCTL_MODE_DIRTYFB
 */
ssize_t drm_ioctl_dirtyfb(drm_device_t *dev, void *arg) {
    (void)dev;
    (void)arg;
    return 0;
}

/**
 * drm_ioctl_mode_list_lessees - Handle DRM_IOCTL_MODE_LIST_LESSEES
 */
ssize_t drm_ioctl_mode_list_lessees(drm_device_t *dev, void *arg) {
    struct drm_mode_list_lessees *l = (struct drm_mode_list_lessees *)arg;
    (void)dev;

    l->count_lessees = 0;
    return 0;
}

static bool drm_ioctl_allow_on_render_node(drm_device_t *dev, uint32_t cmd) {
    uint32_t nr = _IOC_NR(cmd);

    if (nr >= DRM_COMMAND_BASE && nr < DRM_COMMAND_END) {
        return dev && dev->op && dev->op->driver_ioctl;
    }

    switch (cmd) {
    case DRM_IOCTL_VERSION:
    case DRM_IOCTL_GET_CAP:
    case DRM_IOCTL_GEM_CLOSE:
    case DRM_IOCTL_PRIME_HANDLE_TO_FD:
    case DRM_IOCTL_PRIME_FD_TO_HANDLE:
    case DRM_IOCTL_MODE_CREATE_DUMB:
    case DRM_IOCTL_MODE_MAP_DUMB:
    case DRM_IOCTL_MODE_DESTROY_DUMB:
    case DRM_IOCTL_SET_CLIENT_CAP:
        return true;
    default:
        return false;
    }
}

/**
 * drm_ioctl - Main DRM ioctl handler
 */
ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg) {
    drm_device_t *dev = drm_data_to_device(data);
    if (!dev) {
        return -ENODEV;
    }

    uint32_t ioctl_cmd = (uint32_t)(cmd & 0xffffffff);
    if (drm_data_is_render_node(data) &&
        !drm_ioctl_allow_on_render_node(dev, ioctl_cmd)) {
        return -EACCES;
    }

    uint32_t ioctl_dir = _IOC_DIR(ioctl_cmd);
    size_t ioctl_size = _IOC_SIZE(ioctl_cmd);
    void *ioarg = (void *)(uintptr_t)arg;
    void *karg = NULL;

    if (ioctl_size > 0) {
        karg = malloc(ioctl_size);
        if (!karg) {
            return -ENOMEM;
        }
        memset(karg, 0, ioctl_size);

        if (ioctl_dir & _IOC_WRITE) {
            if (!arg ||
                copy_from_user(karg, (void *)(uintptr_t)arg, ioctl_size)) {
                free(karg);
                return -EFAULT;
            }
        }

        ioarg = karg;
    }

    ssize_t ret = -EINVAL;

    switch (ioctl_cmd) {
    case DRM_IOCTL_VERSION:
        ret = drm_ioctl_version(dev, ioarg);
        break;
    case DRM_IOCTL_GET_CAP:
        ret = drm_ioctl_get_cap(dev, ioarg);
        break;
    case DRM_IOCTL_GEM_CLOSE:
        ret = drm_ioctl_gem_close(dev, ioarg);
        break;
    case DRM_IOCTL_PRIME_HANDLE_TO_FD:
        ret = drm_ioctl_prime_handle_to_fd(dev, ioarg);
        break;
    case DRM_IOCTL_PRIME_FD_TO_HANDLE:
        ret = drm_ioctl_prime_fd_to_handle(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETRESOURCES:
        ret = drm_ioctl_mode_getresources(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETCRTC:
        ret = drm_ioctl_mode_getcrtc(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETENCODER:
        ret = drm_ioctl_mode_getencoder(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_CREATE_DUMB:
        ret = drm_ioctl_mode_create_dumb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_MAP_DUMB:
        ret = drm_ioctl_mode_map_dumb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_DESTROY_DUMB:
        ret = drm_ioctl_mode_destroy_dumb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETCONNECTOR:
        ret = drm_ioctl_mode_getconnector(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETFB:
        ret = drm_ioctl_mode_getfb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_ADDFB:
        ret = drm_ioctl_mode_addfb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_ADDFB2:
        ret = drm_ioctl_mode_addfb2(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_RMFB:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_MODE_SETCRTC:
        ret = drm_ioctl_mode_setcrtc(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETPLANERESOURCES:
        ret = drm_ioctl_mode_getplaneresources(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETPLANE:
        ret = drm_ioctl_mode_getplane(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_SETPLANE:
        ret = drm_ioctl_mode_setplane(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETPROPERTY:
        ret = drm_ioctl_mode_getproperty(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETPROPBLOB:
        ret = drm_ioctl_mode_getpropblob(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_CREATEPROPBLOB:
        ret = drm_ioctl_mode_createpropblob(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_DESTROYPROPBLOB:
        ret = drm_ioctl_mode_destroypropblob(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_SETPROPERTY:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_MODE_OBJ_GETPROPERTIES:
        ret = drm_ioctl_mode_obj_getproperties(dev, ioarg);
        break;
    case DRM_IOCTL_SET_CLIENT_CAP:
        ret = drm_ioctl_set_client_cap(dev, ioarg);
        break;
    case DRM_IOCTL_SET_MASTER:
        ret = drm_ioctl_set_master(dev, ioarg);
        break;
    case DRM_IOCTL_DROP_MASTER:
        ret = drm_ioctl_drop_master(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_GETGAMMA:
        ret = drm_ioctl_gamma(dev, ioarg, cmd);
        break;
    case DRM_IOCTL_MODE_SETGAMMA:
        ret = drm_ioctl_gamma(dev, ioarg, cmd);
        break;
    case DRM_IOCTL_MODE_DIRTYFB:
        ret = drm_ioctl_dirtyfb(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_PAGE_FLIP:
        ret = drm_ioctl_page_flip(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_CURSOR:
        ret = drm_ioctl_cursor(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_CURSOR2:
        ret = drm_ioctl_cursor2(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_ATOMIC:
        ret = drm_ioctl_atomic(dev, ioarg);
        break;
    case DRM_IOCTL_WAIT_VBLANK:
        ret = drm_ioctl_wait_vblank(dev, ioarg);
        break;
    case DRM_IOCTL_GET_UNIQUE:
        ret = drm_ioctl_get_unique(dev, ioarg);
        break;
    case DRM_IOCTL_MODE_LIST_LESSEES:
        ret = drm_ioctl_mode_list_lessees(dev, ioarg);
        break;
    case DRM_IOCTL_SET_VERSION:
        ret = 0; // Not implemented
        break;
    case DRM_IOCTL_GET_MAGIC:
        ret = drm_ioctl_get_magic(dev, ioarg);
        break;
    case DRM_IOCTL_AUTH_MAGIC:
        ret = drm_ioctl_auth_magic(dev, ioarg);
        break;
    default:
        if (dev->op && dev->op->driver_ioctl) {
            ret = dev->op->driver_ioctl(dev, ioctl_cmd, ioarg,
                                        drm_data_is_render_node(data));
        } else {
            printk("drm: Unsupported ioctl: cmd = %#010lx\n", cmd);
            ret = -EINVAL;
        }
        break;
    }

    if (ret >= 0 && karg && (ioctl_dir & _IOC_READ)) {
        if (!arg || copy_to_user((void *)(uintptr_t)arg, karg, ioctl_size)) {
            ret = -EFAULT;
        }
    }

    if (karg) {
        free(karg);
    }

    return ret;
}
