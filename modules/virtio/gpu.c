// Copyright (C) 2025-2026  lihanrui2913
#include "gpu.h"
#include "pci.h"
#include <fs/fs_syscall.h>
#include <libs/aether/drm.h>
#include <libs/aether/mm.h>
#include <libs/klibc.h>

virtio_gpu_device_t *virtio_gpu_devices[MAX_VIRTIO_GPU_DEVICES];
uint32_t virtio_gpu_devices_count = 0;

#define VIRTIO_GPU_CMD_TIMEOUT_NS 5000000000ULL
#define VIRTGPU_BLOB_FLAG_MASK                                                 \
    (VIRTGPU_BLOB_FLAG_USE_MAPPABLE | VIRTGPU_BLOB_FLAG_USE_SHAREABLE |        \
     VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE)
#ifndef VIRTGPU_PARAM_CREATE_FENCE_PASSING
#define VIRTGPU_PARAM_CREATE_FENCE_PASSING 9
#endif
#ifndef VIRTGPU_PARAM_CREATE_GUEST_HANDLE
#define VIRTGPU_PARAM_CREATE_GUEST_HANDLE 10
#endif
#define VIRTGPU_DRM_CAPSET_WIRE_FORMAT_VERSION 2

typedef struct virtgpu_drm_capset_compat {
    uint32_t wire_format_version;
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t version_patchlevel;
    uint32_t context_type;
    uint32_t pad[35];
} virtgpu_drm_capset_compat_t;

static int virtio_gpu_resource_unmap_blob(virtio_gpu_device_t *gpu_dev,
                                          uint32_t resource_id,
                                          uint32_t ctx_id);
static int virtio_gpu_resource_map_blob(virtio_gpu_device_t *gpu_dev,
                                        uint32_t resource_id, uint32_t ctx_id,
                                        uint64_t offset,
                                        uint32_t *map_info_out);
static int virtio_gpu_detach_resource_from_ctx(virtio_gpu_device_t *gpu_dev,
                                               uint32_t ctx_id,
                                               uint32_t resource_id);

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

    void *cmd_buf = alloc_frames_bytes(cmd_size);
    void *resp_buf = alloc_frames_bytes(resp_size);
    if (!cmd_buf || !resp_buf) {
        if (cmd_buf) {
            free_frames_bytes(cmd_buf, cmd_size);
        }
        if (resp_buf) {
            free_frames_bytes(resp_buf, resp_size);
        }
        return -ENOMEM;
    }

    memcpy(cmd_buf, cmd, cmd_size);
    memset(resp_buf, 0, resp_size);

    virtio_buffer_t bufs[2];
    bool writable[2];

    // Command buffer (write-only)
    bufs[0].addr = (uint64_t)cmd_buf;
    bufs[0].size = cmd_size;
    writable[0] = false;

    // Response buffer (read-only)
    bufs[1].addr = (uint64_t)resp_buf;
    bufs[1].size = resp_size;
    writable[1] = true;

    spin_lock(&gpu_dev->lock);

    if (cmd_size >= sizeof(virtio_gpu_ctrl_hdr_t)) {
        virtio_gpu_ctrl_hdr_t *hdr = (virtio_gpu_ctrl_hdr_t *)cmd_buf;
        hdr->flags |= VIRTIO_GPU_FLAG_FENCE;
        if (hdr->fence_id == 0) {
            hdr->fence_id = ++gpu_dev->fence_seq;
            if (hdr->fence_id == 0) {
                hdr->fence_id = ++gpu_dev->fence_seq;
            }
        }
    }

    uint16_t desc_idx =
        virt_queue_add_buf(gpu_dev->control_queue, bufs, 2, writable);
    if (desc_idx == 0xFFFF) {
        spin_unlock(&gpu_dev->lock);
        free_frames_bytes(cmd_buf, cmd_size);
        free_frames_bytes(resp_buf, resp_size);
        return -1;
    }

    virt_queue_submit_buf(gpu_dev->control_queue, desc_idx);
    virt_queue_notify(gpu_dev->driver, gpu_dev->control_queue);

    // Wait for response
    uint32_t len;
    uint16_t used_desc_idx;
    uint64_t deadline = nano_time() + VIRTIO_GPU_CMD_TIMEOUT_NS;
    while ((used_desc_idx = virt_queue_get_used_buf(gpu_dev->control_queue,
                                                    &len)) == 0xFFFF) {
        if (nano_time() > deadline) {
            printk("virtio_gpu: command 0x%x timed out\n",
                   ((virtio_gpu_ctrl_hdr_t *)cmd)->type);
            spin_unlock(&gpu_dev->lock);
            free_frames_bytes(cmd_buf, cmd_size);
            free_frames_bytes(resp_buf, resp_size);
            return -ETIMEDOUT;
        }
        arch_pause();
    }

    virt_queue_free_desc(gpu_dev->control_queue, used_desc_idx);
    if (len < sizeof(virtio_gpu_ctrl_hdr_t)) {
        printk("virtio_gpu: short response for cmd %#x len=%u\n",
               ((virtio_gpu_ctrl_hdr_t *)cmd)->type, len);
    } else {
        virtio_gpu_ctrl_hdr_t *resp_hdr = (virtio_gpu_ctrl_hdr_t *)resp_buf;
        if (resp_hdr->type >= VIRTIO_GPU_RESP_ERR_UNSPEC) {
            printk("virtio_gpu: cmd %#x failed, resp=%#x ctx=%u\n",
                   ((virtio_gpu_ctrl_hdr_t *)cmd)->type, resp_hdr->type,
                   resp_hdr->ctx_id);
        }
    }
    memcpy(resp, resp_buf, MIN(resp_size, (size_t)len));
    spin_unlock(&gpu_dev->lock);

    free_frames_bytes(cmd_buf, cmd_size);
    free_frames_bytes(resp_buf, resp_size);
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

static struct virtio_gpu_bo *virtio_gpu_bo_get(virtio_gpu_device_t *gpu_dev,
                                               uint32_t bo_handle) {
    if (!gpu_dev || bo_handle == 0) {
        return NULL;
    }

    for (uint32_t i = 0; i < VIRTIO_GPU_MAX_BOS; i++) {
        if (gpu_dev->bos[i].in_use && gpu_dev->bos[i].bo_handle == bo_handle) {
            return &gpu_dev->bos[i];
        }
    }

    return NULL;
}

static struct virtio_gpu_bo *virtio_gpu_bo_alloc(virtio_gpu_device_t *gpu_dev) {
    if (!gpu_dev) {
        return NULL;
    }

    for (uint32_t i = 0; i < VIRTIO_GPU_MAX_BOS; i++) {
        if (!gpu_dev->bos[i].in_use) {
            memset(&gpu_dev->bos[i], 0, sizeof(gpu_dev->bos[i]));
            gpu_dev->bos[i].in_use = true;
            return &gpu_dev->bos[i];
        }
    }

    return NULL;
}

static int virtio_gpu_alloc_host_visible_offset(virtio_gpu_device_t *gpu_dev,
                                                uint64_t size,
                                                uint64_t *offset_out) {
    if (!gpu_dev || !offset_out || size == 0 ||
        gpu_dev->host_visible_shm_size == 0) {
        return -EINVAL;
    }

    uint64_t aligned_size = PADDING_UP(size, (uint64_t)DEFAULT_PAGE_SIZE);
    if (aligned_size > gpu_dev->host_visible_shm_size) {
        return -ENOSPC;
    }

    uint64_t offset = 0;
    while (offset + aligned_size <= gpu_dev->host_visible_shm_size) {
        bool conflict = false;
        uint64_t next_offset = gpu_dev->host_visible_shm_size;

        for (uint32_t i = 0; i < VIRTIO_GPU_MAX_BOS; i++) {
            struct virtio_gpu_bo *mapped = &gpu_dev->bos[i];
            if (!mapped->in_use || !mapped->blob_mapped || mapped->addr != 0) {
                continue;
            }

            uint64_t mapped_size = mapped->size;
            if (mapped_size == 0) {
                mapped_size = mapped->alloc_size;
            }
            if (mapped_size == 0) {
                continue;
            }
            mapped_size = PADDING_UP(mapped_size, (uint64_t)DEFAULT_PAGE_SIZE);

            uint64_t mapped_start = mapped->host_visible_offset;
            uint64_t mapped_end = mapped_start + mapped_size;
            uint64_t end = offset + aligned_size;
            if (offset < mapped_end && mapped_start < end) {
                conflict = true;
                uint64_t candidate =
                    PADDING_UP(mapped_end, (uint64_t)DEFAULT_PAGE_SIZE);
                if (candidate > offset) {
                    next_offset = MIN(next_offset, candidate);
                }
            }
        }

        if (!conflict) {
            *offset_out = offset;
            return 0;
        }
        if (next_offset <= offset ||
            next_offset > gpu_dev->host_visible_shm_size) {
            return -ENOSPC;
        }
        offset = next_offset;
    }

    return -ENOSPC;
}

static int virtio_gpu_map_host_visible_blob(virtio_gpu_device_t *gpu_dev,
                                            struct virtio_gpu_bo *bo) {
    if (!gpu_dev || !bo || bo->resource_id == 0) {
        return -EINVAL;
    }
    if (bo->blob_mapped) {
        return 0;
    }
    if (!bo->is_blob || bo->addr != 0) {
        return -EOPNOTSUPP;
    }
    if (!(bo->blob_flags & VIRTGPU_BLOB_FLAG_USE_MAPPABLE)) {
        return -EOPNOTSUPP;
    }
    if (bo->blob_mem != VIRTGPU_BLOB_MEM_HOST3D) {
        return -EOPNOTSUPP;
    }
    if (gpu_dev->host_visible_shm_paddr == 0 ||
        gpu_dev->host_visible_shm_size == 0) {
        return -EOPNOTSUPP;
    }

    uint64_t map_size = bo->size ? bo->size : bo->alloc_size;
    if (map_size == 0) {
        return -EINVAL;
    }

    uint64_t offset = 0;
    int ret = virtio_gpu_alloc_host_visible_offset(gpu_dev, map_size, &offset);
    if (ret != 0) {
        return ret;
    }

    uint32_t map_info = 0;
    ret = virtio_gpu_resource_map_blob(gpu_dev, bo->resource_id,
                                       bo->attached_ctx_id, offset, &map_info);
    if (ret != 0) {
        return ret;
    }

    bo->host_visible_offset = offset;
    bo->blob_map_info = map_info;
    bo->blob_mapped = true;
    return 0;
}

static void virtio_gpu_bo_release_resource(virtio_gpu_device_t *gpu_dev,
                                           struct virtio_gpu_bo *bo) {
    if (!gpu_dev || !bo || !bo->in_use) {
        return;
    }

    if (bo->blob_mapped && bo->resource_id) {
        virtio_gpu_resource_unmap_blob(gpu_dev, bo->resource_id,
                                       bo->attached_ctx_id);
    }

    if (bo->resource_id) {
        if (bo->attached_ctx_id) {
            virtio_gpu_detach_resource_from_ctx(gpu_dev, bo->attached_ctx_id,
                                                bo->resource_id);
        }

        if (!bo->is_blob || bo->addr) {
            virtio_gpu_detach_backing(gpu_dev, bo->resource_id);
        }
        virtio_gpu_unref_resource(gpu_dev, bo->resource_id);
    }

    bo->resource_id = 0;
    bo->width = 0;
    bo->height = 0;
    bo->stride = 0;
    bo->format = 0;
    bo->is_blob = false;
    bo->blob_mem = 0;
    bo->blob_flags = 0;
    bo->blob_id = 0;
    bo->blob_mapped = false;
    bo->blob_map_info = 0;
    bo->host_visible_offset = 0;
    bo->attached_ctx_id = 0;
}

static void virtio_gpu_bo_free(virtio_gpu_device_t *gpu_dev,
                               struct virtio_gpu_bo *bo) {
    if (!gpu_dev || !bo || !bo->in_use) {
        return;
    }

    virtio_gpu_bo_release_resource(gpu_dev, bo);

    if (bo->addr) {
        uint64_t free_size = bo->alloc_size;
        if (free_size == 0 && bo->size != 0) {
            free_size = PADDING_UP(bo->size, (uint64_t)DEFAULT_PAGE_SIZE);
        }
        if (free_size) {
            free_frames(bo->addr, free_size / DEFAULT_PAGE_SIZE);
        }
    }

    memset(bo, 0, sizeof(*bo));
}

static uint32_t virtio_gpu_alloc_bo_handle(virtio_gpu_device_t *gpu_dev) {
    if (!gpu_dev) {
        return 0;
    }

    for (uint32_t attempt = 0; attempt < 0xFFFF; attempt++) {
        uint32_t candidate = gpu_dev->next_bo_handle++;
        if (candidate == 0 || candidate <= 32) {
            continue;
        }
        if (!virtio_gpu_bo_get(gpu_dev, candidate)) {
            return candidate;
        }
    }

    return 0;
}

static int virtio_gpu_create_resource_3d(virtio_gpu_device_t *gpu_dev,
                                         uint32_t resource_id, uint32_t target,
                                         uint32_t format, uint32_t bind,
                                         uint32_t width, uint32_t height,
                                         uint32_t depth, uint32_t array_size,
                                         uint32_t last_level,
                                         uint32_t nr_samples, uint32_t flags) {
    virtio_gpu_resource_create_3d_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_3D},
        .resource_id = resource_id,
        .target = target,
        .format = format,
        .bind = bind,
        .width = width,
        .height = height,
        .depth = depth,
        .array_size = array_size,
        .last_level = last_level,
        .nr_samples = nr_samples,
        .flags = flags,
        .padding = 0,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_create_resource_blob(virtio_gpu_device_t *gpu_dev,
                                           uint32_t resource_id,
                                           uint32_t blob_mem,
                                           uint32_t blob_flags,
                                           uint64_t blob_id, uint64_t size,
                                           uint64_t addr, uint32_t ctx_id) {
    if (addr && size > UINT32_MAX) {
        return -E2BIG;
    }

    virtio_gpu_resource_create_blob_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB, .ctx_id = ctx_id},
        .resource_id = resource_id,
        .blob_mem = blob_mem,
        .blob_flags = blob_flags,
        .nr_entries = addr ? 1U : 0U,
        .blob_id = blob_id,
        .size = size,
        .mem_entry = {.addr = addr, .length = (uint32_t)size, .padding = 0},
    };

    size_t cmd_size = sizeof(cmd);
    if (cmd.nr_entries == 0) {
        cmd_size -= sizeof(cmd.mem_entry);
    }

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret =
        virtio_gpu_send_command(gpu_dev, &cmd, cmd_size, &resp, sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_resource_map_blob(virtio_gpu_device_t *gpu_dev,
                                        uint32_t resource_id, uint32_t ctx_id,
                                        uint64_t offset,
                                        uint32_t *map_info_out) {
    if (!gpu_dev) {
        return -EINVAL;
    }

    virtio_gpu_resource_map_blob_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB, .ctx_id = ctx_id},
        .resource_id = resource_id,
        .padding = 0,
        .offset = offset,
    };

    virtio_gpu_resp_map_info_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }
    if (resp.hdr.type != VIRTIO_GPU_RESP_OK_MAP_INFO) {
        return -EIO;
    }

    if (map_info_out) {
        *map_info_out = resp.map_info;
    }
    return 0;
}

static int virtio_gpu_resource_unmap_blob(virtio_gpu_device_t *gpu_dev,
                                          uint32_t resource_id,
                                          uint32_t ctx_id) {
    if (!gpu_dev) {
        return -EINVAL;
    }

    virtio_gpu_resource_unmap_blob_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB, .ctx_id = ctx_id},
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

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_create_context(virtio_gpu_device_t *gpu_dev,
                                     uint32_t ctx_id, uint32_t capset_id) {
    if (!gpu_dev || ctx_id == 0) {
        return -EINVAL;
    }

    virtio_gpu_ctx_create_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_CTX_CREATE, .ctx_id = ctx_id},
        .nlen = 0,
        .context_init = 0,
    };

    if (gpu_dev->negotiated_features & VIRTIO_GPU_F_CONTEXT_INIT) {
        cmd.context_init = capset_id & 0xFF;
    }

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_attach_resource_to_ctx(virtio_gpu_device_t *gpu_dev,
                                             uint32_t ctx_id,
                                             uint32_t resource_id) {
    virtio_gpu_ctx_resource_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, .ctx_id = ctx_id},
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

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_detach_resource_from_ctx(virtio_gpu_device_t *gpu_dev,
                                               uint32_t ctx_id,
                                               uint32_t resource_id) {
    if (!gpu_dev || ctx_id == 0 || resource_id == 0) {
        return -EINVAL;
    }

    virtio_gpu_ctx_resource_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE, .ctx_id = ctx_id},
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

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_submit_3d(virtio_gpu_device_t *gpu_dev, uint32_t ctx_id,
                                const void *command, uint32_t size) {
    if (!gpu_dev || !command || size == 0) {
        return -EINVAL;
    }

    size_t submit_size = sizeof(virtio_gpu_cmd_submit_t) + size;
    virtio_gpu_cmd_submit_t *cmd = malloc(submit_size);
    if (!cmd) {
        return -ENOMEM;
    }

    memset(cmd, 0, submit_size);
    cmd->hdr.type = VIRTIO_GPU_CMD_SUBMIT_3D;
    cmd->hdr.ctx_id = ctx_id;
    cmd->size = size;
    cmd->padding = 0;
    memcpy(cmd->data, command, size);

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret =
        virtio_gpu_send_command(gpu_dev, cmd, submit_size, &resp, sizeof(resp));
    free(cmd);
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_transfer_to_host_3d(virtio_gpu_device_t *gpu_dev,
                                          uint32_t resource_id,
                                          const struct drm_virtgpu_3d_box *box,
                                          uint32_t level, uint32_t offset,
                                          uint32_t stride,
                                          uint32_t layer_stride) {
    if (!gpu_dev || !box) {
        return -EINVAL;
    }

    virtio_gpu_transfer_host_3d_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D},
        .box.x = box->x,
        .box.y = box->y,
        .box.z = box->z,
        .box.w = box->w,
        .box.h = box->h,
        .box.d = box->d,
        .offset = offset,
        .resource_id = resource_id,
        .level = level,
        .stride = stride,
        .layer_stride = layer_stride,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_transfer_from_host_3d(
    virtio_gpu_device_t *gpu_dev, uint32_t resource_id,
    const struct drm_virtgpu_3d_box *box, uint32_t level, uint32_t offset,
    uint32_t stride, uint32_t layer_stride) {
    if (!gpu_dev || !box) {
        return -EINVAL;
    }

    virtio_gpu_transfer_host_3d_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D},
        .box.x = box->x,
        .box.y = box->y,
        .box.z = box->z,
        .box.w = box->w,
        .box.h = box->h,
        .box.d = box->d,
        .offset = offset,
        .resource_id = resource_id,
        .level = level,
        .stride = stride,
        .layer_stride = layer_stride,
    };

    virtio_gpu_ctrl_hdr_t resp;
    memset(&resp, 0, sizeof(resp));

    int ret = virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), &resp,
                                      sizeof(resp));
    if (ret != 0) {
        return ret;
    }

    return resp.type == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -EIO;
}

static int virtio_gpu_get_capset_info(virtio_gpu_device_t *gpu_dev,
                                      uint32_t capset_index,
                                      virtio_gpu_resp_capset_info_t *out) {
    if (!gpu_dev || !out) {
        return -EINVAL;
    }

    virtio_gpu_get_capset_info_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_GET_CAPSET_INFO},
        .capset_index = capset_index,
        .padding = 0,
    };

    memset(out, 0, sizeof(*out));
    int ret =
        virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), out, sizeof(*out));
    if (ret != 0) {
        return ret;
    }

    return out->hdr.type == VIRTIO_GPU_RESP_OK_CAPSET_INFO ? 0 : -ENOENT;
}

static int virtio_gpu_find_capset_info(virtio_gpu_device_t *gpu_dev,
                                       uint32_t capset_id,
                                       virtio_gpu_resp_capset_info_t *out) {
    if (!gpu_dev || !out || capset_id == 0) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < 64; i++) {
        virtio_gpu_resp_capset_info_t info;
        if (virtio_gpu_get_capset_info(gpu_dev, i, &info) != 0) {
            break;
        }
        if (info.capset_id == capset_id) {
            *out = info;
            return 0;
        }
    }

    return -ENOENT;
}

static int virtio_gpu_get_capset(virtio_gpu_device_t *gpu_dev,
                                 uint32_t capset_id, uint32_t version,
                                 void *data, uint32_t data_size) {
    if (!gpu_dev || !data || data_size == 0) {
        return -EINVAL;
    }

    virtio_gpu_get_capset_t cmd = {
        .hdr = {.type = VIRTIO_GPU_CMD_GET_CAPSET},
        .capset_id = capset_id,
        .capset_version = version,
    };

    size_t resp_size = sizeof(virtio_gpu_ctrl_hdr_t) + data_size;
    uint8_t *resp = malloc(resp_size);
    if (!resp) {
        return -ENOMEM;
    }

    memset(resp, 0, resp_size);
    int ret =
        virtio_gpu_send_command(gpu_dev, &cmd, sizeof(cmd), resp, resp_size);
    if (ret == 0) {
        virtio_gpu_ctrl_hdr_t *hdr = (virtio_gpu_ctrl_hdr_t *)resp;
        if (hdr->type == VIRTIO_GPU_RESP_OK_CAPSET) {
            memcpy(data, resp + sizeof(virtio_gpu_ctrl_hdr_t), data_size);
            ret = 0;
        } else {
            ret = -EIO;
        }
    }

    free(resp);
    return ret;
}

static void virtio_gpu_refresh_capset_mask(virtio_gpu_device_t *gpu_dev);

static uint32_t virtio_gpu_normalize_capset_id(virtio_gpu_device_t *gpu_dev,
                                               uint32_t capset_id) {
    if (capset_id == VIRTGPU_DRM_CAPSET_DRM && gpu_dev &&
        gpu_dev->virgl_enabled) {
        return VIRTGPU_DRM_CAPSET_VIRGL;
    }
    return capset_id;
}

static int virtio_gpu_ensure_context(virtio_gpu_device_t *gpu_dev,
                                     uint32_t capset_id) {
    if (!gpu_dev) {
        return -EINVAL;
    }

    uint32_t effective_capset_id =
        virtio_gpu_normalize_capset_id(gpu_dev, capset_id);

    if (effective_capset_id != 0) {
        if (gpu_dev->supported_capset_mask == 0) {
            virtio_gpu_refresh_capset_mask(gpu_dev);
        }
        if (gpu_dev->supported_capset_mask &&
            (effective_capset_id >= 64 || !(gpu_dev->supported_capset_mask &
                                            (1ULL << effective_capset_id)))) {
            return -EINVAL;
        }
    }

    if (gpu_dev->context_initialized) {
        if (gpu_dev->active_capset_id == 0) {
            gpu_dev->active_capset_id = effective_capset_id;
        }
        return 0;
    }

    if (!gpu_dev->virgl_enabled) {
        return -EOPNOTSUPP;
    }

    uint32_t ctx_id = gpu_dev->active_ctx_id;
    if (ctx_id == 0) {
        ctx_id = 1;
    }

    int ret = virtio_gpu_create_context(gpu_dev, ctx_id, effective_capset_id);
    if (ret == 0) {
        gpu_dev->active_ctx_id = ctx_id;
        gpu_dev->active_capset_id = effective_capset_id;
        gpu_dev->context_initialized = true;
    }
    return ret;
}

static void virtio_gpu_refresh_capset_mask(virtio_gpu_device_t *gpu_dev) {
    if (!gpu_dev) {
        return;
    }

    uint64_t mask = 0;
    for (uint32_t i = 0; i < 64; i++) {
        virtio_gpu_resp_capset_info_t info;
        if (virtio_gpu_get_capset_info(gpu_dev, i, &info) != 0) {
            break;
        }
        if (info.capset_id > 0 && info.capset_id < 64) {
            mask |= 1ULL << info.capset_id;
        }
    }

    if (mask == 0 && gpu_dev->virgl_enabled) {
        mask |= 1ULL << VIRTGPU_DRM_CAPSET_VIRGL;
    }
    if (gpu_dev->virgl_enabled) {
        mask |= 1ULL << VIRTGPU_DRM_CAPSET_DRM;
    }

    gpu_dev->supported_capset_mask = mask;
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
    fb->format = DRM_FORMAT_XRGB8888;

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

    switch (fb_cmd->pixel_format) {
    case DRM_FORMAT_XRGB8888:
    case DRM_FORMAT_ARGB8888:
        break;
    default:
        drm_framebuffer_free(&device->resource_mgr, fb->id);
        return -EINVAL;
    }

    fb->width = fb_cmd->width;
    fb->height = fb_cmd->height;
    fb->pitch = fb_cmd->pitches[0];
    fb->bpp = 32;
    fb->depth = (fb_cmd->pixel_format == DRM_FORMAT_ARGB8888) ? 32 : 24;
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

static bool virtio_gpu_is_private_ioctl(uint32_t cmd) {
    switch (cmd) {
    case DRM_IOCTL_VIRTGPU_GETPARAM:
    case DRM_IOCTL_VIRTGPU_CONTEXT_INIT:
    case DRM_IOCTL_VIRTGPU_GET_CAPS:
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE:
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB:
    case DRM_IOCTL_VIRTGPU_RESOURCE_INFO:
    case DRM_IOCTL_VIRTGPU_MAP:
    case DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST:
    case DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST:
    case DRM_IOCTL_VIRTGPU_EXECBUFFER:
    case DRM_IOCTL_VIRTGPU_WAIT:
        return true;
    default:
        return false;
    }
}

static ssize_t virtio_gpu_write_u64_to_user(uint64_t user_ptr, uint64_t value) {
    if (user_ptr == 0) {
        return -EINVAL;
    }
    if (copy_to_user((void *)(uintptr_t)user_ptr, &value, sizeof(value))) {
        return -EFAULT;
    }
    return 0;
}

static int virtio_gpu_copy_from_user_alloc(uint64_t user_ptr, uint32_t size,
                                           void **out_buf) {
    if (!out_buf || !user_ptr || size == 0) {
        return -EINVAL;
    }

    void *buf = malloc(size);
    if (!buf) {
        return -ENOMEM;
    }

    if (copy_from_user(buf, (const void *)(uintptr_t)user_ptr, size)) {
        free(buf);
        return -EFAULT;
    }

    *out_buf = buf;
    return 0;
}

static int virtio_gpu_wait_fence_fd_in(int fence_fd) {
    if (fence_fd < 0 || fence_fd >= MAX_FD_NUM) {
        return -EBADF;
    }

    vfs_node_t node = NULL;
    with_fd_info_lock(current_task->fd_info, {
        fd_t *fd = current_task->fd_info->fds[fence_fd];
        if (fd && fd->node) {
            node = fd->node;
            node->refcount++;
        }
    });

    if (!node) {
        return -EBADF;
    }

    int ret = 0;
    uint32_t want = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLNVAL;

    int events = vfs_poll(node, want);
    if (events < 0) {
        ret = events;
        goto out;
    }
    if (events & EPOLLIN) {
        ret = 0;
        goto out;
    }
    if (events & (EPOLLERR | EPOLLHUP | EPOLLNVAL)) {
        ret = -EIO;
        goto out;
    }

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
    ret = vfs_poll_wait_arm(node, &wait);
    if (ret != 0) {
        goto out;
    }

    events = vfs_poll(node, want);
    if (events < 0) {
        vfs_poll_wait_disarm(&wait);
        ret = events;
        goto out;
    }
    if (!(events & want)) {
        int reason =
            vfs_poll_wait_sleep(node, &wait, -1, "virtio_gpu_fence_wait");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK) {
            ret = reason == EINTR ? -EINTR : -EIO;
            goto out;
        }
    } else {
        vfs_poll_wait_disarm(&wait);
    }

    events = vfs_poll(node, want);
    if (events < 0) {
        ret = events;
        goto out;
    }
    if (events & EPOLLIN) {
        ret = 0;
        goto out;
    }
    if (events & (EPOLLERR | EPOLLHUP | EPOLLNVAL)) {
        ret = -EIO;
        goto out;
    }

    ret = -EAGAIN;

out:
    vfs_close(node);
    return ret;
}

static int virtio_gpu_create_signaled_fence_fd_out(void) {
    uint64_t fd = sys_eventfd2(1, EFD_CLOEXEC);
    if ((int64_t)fd < 0) {
        return (int)fd;
    }
    return (int)fd;
}

static ssize_t virtio_gpu_driver_ioctl(drm_device_t *drm_dev, uint32_t cmd,
                                       void *arg, bool render_node) {
    virtio_gpu_device_t *gpu_dev = drm_dev ? drm_dev->data : NULL;
    if (!gpu_dev || !arg) {
        return -EINVAL;
    }

    if (render_node && cmd != DRM_IOCTL_GEM_CLOSE &&
        !virtio_gpu_is_private_ioctl(cmd)) {
        return -EACCES;
    }

    switch (cmd) {
    case DRM_IOCTL_GEM_CLOSE: {
        struct drm_gem_close *close = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, close->handle);
        if (!bo) {
            return -ENOENT;
        }
        virtio_gpu_bo_free(gpu_dev, bo);
        return 0;
    }
    case DRM_IOCTL_VIRTGPU_GETPARAM: {
        struct drm_virtgpu_getparam *req = arg;
        uint64_t value = 0;
        if (gpu_dev->supported_capset_mask == 0) {
            virtio_gpu_refresh_capset_mask(gpu_dev);
        }

        switch (req->param) {
        case VIRTGPU_PARAM_3D_FEATURES:
            value = gpu_dev->virgl_enabled ? 1 : 0;
            break;
        case VIRTGPU_PARAM_CAPSET_QUERY_FIX:
            value = 1;
            break;
        case VIRTGPU_PARAM_RESOURCE_BLOB:
            value =
                !!(gpu_dev->negotiated_features & VIRTIO_GPU_F_RESOURCE_BLOB);
            break;
        case VIRTGPU_PARAM_HOST_VISIBLE:
            value =
                (gpu_dev->host_visible_shm_size &&
                 (gpu_dev->negotiated_features & VIRTIO_GPU_F_RESOURCE_BLOB))
                    ? 1
                    : 0;
            break;
        case VIRTGPU_PARAM_CROSS_DEVICE:
            value = 0;
            break;
        case VIRTGPU_PARAM_CONTEXT_INIT:
            value =
                !!(gpu_dev->negotiated_features & VIRTIO_GPU_F_CONTEXT_INIT);
            break;
        case VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs:
            value = gpu_dev->supported_capset_mask;
            break;
        case VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME:
            value =
                !!(gpu_dev->negotiated_features & VIRTIO_GPU_F_CONTEXT_INIT);
            break;
        case VIRTGPU_PARAM_CREATE_FENCE_PASSING:
            value = 1;
            break;
        case VIRTGPU_PARAM_CREATE_GUEST_HANDLE:
            value = 0;
            break;
        default:
            return -EINVAL;
        }

        return virtio_gpu_write_u64_to_user(req->value, value);
    }
    case DRM_IOCTL_VIRTGPU_CONTEXT_INIT: {
        struct drm_virtgpu_context_init *ctx = arg;
        uint32_t capset_id = VIRTGPU_DRM_CAPSET_VIRGL;
        uint32_t num_rings = 1;
        uint64_t poll_mask = 0;
        if ((ctx->num_params == 0) != (ctx->ctx_set_params == 0)) {
            return -EINVAL;
        }

        if (ctx->num_params) {
            if (ctx->num_params > 64) {
                return -EINVAL;
            }

            uint32_t params_size =
                ctx->num_params * sizeof(struct drm_virtgpu_context_set_param);
            struct drm_virtgpu_context_set_param *params = NULL;
            int ret = virtio_gpu_copy_from_user_alloc(
                ctx->ctx_set_params, params_size, (void **)&params);
            if (ret != 0) {
                return ret;
            }

            for (uint32_t i = 0; i < ctx->num_params; i++) {
                if (params[i].param == VIRTGPU_CONTEXT_PARAM_CAPSET_ID) {
                    capset_id = (uint32_t)params[i].value;
                } else if (params[i].param == VIRTGPU_CONTEXT_PARAM_NUM_RINGS) {
                    num_rings = (uint32_t)params[i].value;
                } else if (params[i].param ==
                           VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK) {
                    poll_mask = params[i].value;
                } else if (params[i].param ==
                           VIRTGPU_CONTEXT_PARAM_DEBUG_NAME) {
                    free(params);
                    return -EOPNOTSUPP;
                } else {
                    free(params);
                    return -EINVAL;
                }
            }
            free(params);
        }
        if (num_rings != 1 || (poll_mask & ~1ULL)) {
            return -EOPNOTSUPP;
        }
        return virtio_gpu_ensure_context(gpu_dev, capset_id);
    }
    case DRM_IOCTL_VIRTGPU_GET_CAPS: {
        struct drm_virtgpu_get_caps *caps = arg;
        if (!caps->addr || caps->size == 0) {
            return -EINVAL;
        }
        if (caps->size > (1U << 20)) {
            return -E2BIG;
        }

        if (caps->cap_set_id == VIRTGPU_DRM_CAPSET_DRM) {
            virtgpu_drm_capset_compat_t drm_caps;
            memset(&drm_caps, 0, sizeof(drm_caps));
            drm_caps.wire_format_version =
                VIRTGPU_DRM_CAPSET_WIRE_FORMAT_VERSION;
            drm_caps.version_major = 1;
            drm_caps.version_minor = 0;
            drm_caps.version_patchlevel = 0;
            drm_caps.context_type = 0;

            uint32_t copy_size = MIN(caps->size, (uint32_t)sizeof(drm_caps));
            if (copy_to_user((void *)(uintptr_t)caps->addr, &drm_caps,
                             copy_size)) {
                return -EFAULT;
            }
            return 0;
        }

        virtio_gpu_resp_capset_info_t info;
        int ret = virtio_gpu_find_capset_info(gpu_dev, caps->cap_set_id, &info);
        if (ret != 0) {
            return -EINVAL;
        }

        uint32_t capset_version = caps->cap_set_ver;
        if (capset_version == 0 || capset_version > info.capset_max_version) {
            capset_version = info.capset_max_version;
        }

        if (capset_version == 0 || info.capset_max_size == 0) {
            return -EINVAL;
        }

        uint32_t copy_size = MIN(caps->size, info.capset_max_size);
        void *capbuf = malloc(caps->size);
        if (!capbuf) {
            return -ENOMEM;
        }
        memset(capbuf, 0, caps->size);
        ret = virtio_gpu_get_capset(gpu_dev, caps->cap_set_id, capset_version,
                                    capbuf, copy_size);
        if (ret == 0) {
            if (copy_to_user((void *)(uintptr_t)caps->addr, capbuf,
                             copy_size)) {
                ret = -EFAULT;
            }
        }
        free(capbuf);
        return ret;
    }
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE: {
        struct drm_virtgpu_resource_create *req = arg;
        if (!gpu_dev->virgl_enabled) {
            return -EOPNOTSUPP;
        }
        if (req->width == 0 || req->height == 0) {
            return -EINVAL;
        }

        bool reuse_bo = req->bo_handle != 0;
        struct virtio_gpu_bo *bo =
            reuse_bo ? virtio_gpu_bo_get(gpu_dev, req->bo_handle)
                     : virtio_gpu_bo_alloc(gpu_dev);
        if (!bo) {
            return reuse_bo ? -ENOENT : -ENOSPC;
        }
        if (reuse_bo && bo->resource_id != 0) {
            virtio_gpu_bo_release_resource(gpu_dev, bo);
        }

        uint32_t resource_id = 0;
        int ret = virtio_gpu_alloc_resource_id(gpu_dev, &resource_id);
        if (ret != 0) {
            if (!reuse_bo) {
                memset(bo, 0, sizeof(*bo));
            }
            return ret;
        }

        uint64_t size = req->size;
        if (size == 0 && reuse_bo) {
            size = bo->size;
        }
        if (size == 0) {
            uint64_t depth = req->depth ? req->depth : 1;
            size = (uint64_t)req->width * req->height * depth * 4;
        }
        size = MAX(size, (uint64_t)DEFAULT_PAGE_SIZE);
        if (size > UINT32_MAX) {
            if (!reuse_bo) {
                memset(bo, 0, sizeof(*bo));
            }
            return -E2BIG;
        }

        uint64_t alloc_size = 0;
        uint64_t addr = 0;
        if (reuse_bo) {
            uint64_t max_size = bo->alloc_size ? bo->alloc_size : bo->size;
            if (!bo->addr || max_size == 0 || size > max_size) {
                return -EINVAL;
            }
            addr = bo->addr;
            alloc_size = max_size;
        } else {
            alloc_size = PADDING_UP(size, (uint64_t)DEFAULT_PAGE_SIZE);
            addr = alloc_frames(alloc_size / DEFAULT_PAGE_SIZE);
            if (!addr) {
                memset(bo, 0, sizeof(*bo));
                return -ENOMEM;
            }
            memset((void *)phys_to_virt(addr), 0, alloc_size);
        }

        ret = virtio_gpu_create_resource_3d(
            gpu_dev, resource_id, req->target, req->format, req->bind,
            req->width, req->height, req->depth ? req->depth : 1,
            req->array_size ? req->array_size : 1, req->last_level,
            req->nr_samples, req->flags);
        if (ret != 0) {
            if (!reuse_bo) {
                free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                memset(bo, 0, sizeof(*bo));
            }
            return ret;
        }

        ret = virtio_gpu_attach_backing(gpu_dev, resource_id, addr,
                                        (uint32_t)size);
        if (ret != 0) {
            virtio_gpu_unref_resource(gpu_dev, resource_id);
            if (!reuse_bo) {
                free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                memset(bo, 0, sizeof(*bo));
            }
            return ret;
        }

        uint32_t bo_handle = req->bo_handle;
        if (!reuse_bo) {
            bo_handle = virtio_gpu_alloc_bo_handle(gpu_dev);
            if (bo_handle == 0) {
                virtio_gpu_detach_backing(gpu_dev, resource_id);
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                memset(bo, 0, sizeof(*bo));
                return -ENOSPC;
            }
        }

        bo->bo_handle = bo_handle;
        bo->resource_id = resource_id;
        bo->addr = addr;
        bo->size = size;
        bo->alloc_size = alloc_size;
        bo->width = req->width;
        bo->height = req->height;
        bo->stride = req->stride ? req->stride : req->width * 4;
        bo->format = req->format;
        bo->is_blob = false;
        bo->blob_mem = 0;
        bo->blob_flags = 0;
        bo->blob_id = 0;
        bo->blob_mapped = false;
        bo->blob_map_info = 0;
        bo->host_visible_offset = 0;
        bo->attached_ctx_id = 0;

        req->bo_handle = bo_handle;
        req->res_handle = resource_id;
        req->size = (uint32_t)size;
        if (req->stride == 0) {
            req->stride = bo->stride;
        }
        return 0;
    }
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB: {
        struct drm_virtgpu_resource_create_blob *req = arg;
        if (!(gpu_dev->negotiated_features & VIRTIO_GPU_F_RESOURCE_BLOB)) {
            return -EOPNOTSUPP;
        }
        if (req->size == 0) {
            return -EINVAL;
        }
        if ((req->cmd_size == 0) != (req->cmd == 0)) {
            return -EINVAL;
        }
        if (req->cmd_size > (1U << 20)) {
            return -E2BIG;
        }
        if (req->blob_flags & ~VIRTGPU_BLOB_FLAG_MASK) {
            return -EINVAL;
        }
        if (req->blob_mem != VIRTGPU_BLOB_MEM_GUEST &&
            req->blob_mem != VIRTGPU_BLOB_MEM_HOST3D &&
            req->blob_mem != VIRTGPU_BLOB_MEM_HOST3D_GUEST) {
            return -EINVAL;
        }
        if ((req->blob_mem == VIRTGPU_BLOB_MEM_GUEST ||
             req->blob_mem == VIRTGPU_BLOB_MEM_HOST3D_GUEST) &&
            req->size > UINT32_MAX) {
            return -E2BIG;
        }
        if (req->blob_mem == VIRTGPU_BLOB_MEM_HOST3D &&
            (req->blob_flags & VIRTGPU_BLOB_FLAG_USE_MAPPABLE) &&
            gpu_dev->host_visible_shm_size == 0) {
            return -EOPNOTSUPP;
        }

        bool reuse_bo = req->bo_handle != 0;
        struct virtio_gpu_bo *bo =
            reuse_bo ? virtio_gpu_bo_get(gpu_dev, req->bo_handle)
                     : virtio_gpu_bo_alloc(gpu_dev);
        if (!bo) {
            return reuse_bo ? -ENOENT : -ENOSPC;
        }
        if (reuse_bo && bo->resource_id != 0) {
            virtio_gpu_bo_release_resource(gpu_dev, bo);
        }

        uint32_t resource_id = 0;
        int ret = virtio_gpu_alloc_resource_id(gpu_dev, &resource_id);
        if (ret != 0) {
            if (!reuse_bo) {
                memset(bo, 0, sizeof(*bo));
            }
            return ret;
        }

        uint64_t alloc_size = 0;
        uint64_t addr = 0;
        if (req->blob_mem == VIRTGPU_BLOB_MEM_GUEST ||
            req->blob_mem == VIRTGPU_BLOB_MEM_HOST3D_GUEST) {
            if (reuse_bo) {
                uint64_t max_size = bo->alloc_size ? bo->alloc_size : bo->size;
                if (!bo->addr || max_size == 0 || req->size > max_size) {
                    return -EINVAL;
                }
                addr = bo->addr;
                alloc_size = max_size;
            } else {
                alloc_size = PADDING_UP(req->size, (uint64_t)DEFAULT_PAGE_SIZE);
                addr = alloc_frames(alloc_size / DEFAULT_PAGE_SIZE);
                if (!addr) {
                    memset(bo, 0, sizeof(*bo));
                    return -ENOMEM;
                }
                memset((void *)phys_to_virt(addr), 0, alloc_size);
            }
        } else if (reuse_bo && (bo->alloc_size || bo->size)) {
            alloc_size = bo->alloc_size ? bo->alloc_size : bo->size;
        } else {
            alloc_size = PADDING_UP(req->size, (uint64_t)DEFAULT_PAGE_SIZE);
        }

        uint32_t create_ctx_id = 0;
        if (req->blob_mem != VIRTGPU_BLOB_MEM_GUEST || req->cmd_size > 0) {
            uint32_t capset_id = gpu_dev->active_capset_id
                                     ? gpu_dev->active_capset_id
                                     : VIRTGPU_DRM_CAPSET_VIRGL;
            ret = virtio_gpu_ensure_context(gpu_dev, capset_id);
            if (ret != 0) {
                if (!reuse_bo && addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                if (!reuse_bo) {
                    memset(bo, 0, sizeof(*bo));
                }
                return ret;
            }
            create_ctx_id = gpu_dev->active_ctx_id;
        }

        ret = virtio_gpu_create_resource_blob(
            gpu_dev, resource_id, req->blob_mem, req->blob_flags, req->blob_id,
            req->size, addr, create_ctx_id);
        if (ret != 0) {
            if (!reuse_bo && addr) {
                free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
            }
            if (!reuse_bo) {
                memset(bo, 0, sizeof(*bo));
            }
            return ret;
        }

        if (req->cmd_size && req->cmd) {
            if (!gpu_dev->context_initialized) {
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                if (!reuse_bo && addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                if (!reuse_bo) {
                    memset(bo, 0, sizeof(*bo));
                }
                return -EOPNOTSUPP;
            }

            void *cmd_data = NULL;
            ret = virtio_gpu_copy_from_user_alloc(req->cmd, req->cmd_size,
                                                  &cmd_data);
            if (ret != 0) {
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                if (!reuse_bo && addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                if (!reuse_bo) {
                    memset(bo, 0, sizeof(*bo));
                }
                return ret;
            }

            ret = virtio_gpu_attach_resource_to_ctx(
                gpu_dev, gpu_dev->active_ctx_id, resource_id);
            if (ret != 0) {
                free(cmd_data);
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                if (!reuse_bo && addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                if (!reuse_bo) {
                    memset(bo, 0, sizeof(*bo));
                }
                return ret;
            }

            ret = virtio_gpu_submit_3d(gpu_dev, gpu_dev->active_ctx_id,
                                       cmd_data, req->cmd_size);
            free(cmd_data);
            if (ret != 0) {
                virtio_gpu_detach_resource_from_ctx(
                    gpu_dev, gpu_dev->active_ctx_id, resource_id);
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                if (!reuse_bo && addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                if (!reuse_bo) {
                    memset(bo, 0, sizeof(*bo));
                }
                return ret;
            }

            bo->attached_ctx_id = gpu_dev->active_ctx_id;
        }

        uint32_t bo_handle = req->bo_handle;
        if (!reuse_bo) {
            bo_handle = virtio_gpu_alloc_bo_handle(gpu_dev);
            if (bo_handle == 0) {
                uint32_t detach_ctx_id = bo->attached_ctx_id;
                if (detach_ctx_id == 0) {
                    detach_ctx_id = create_ctx_id;
                }
                if (detach_ctx_id) {
                    virtio_gpu_detach_resource_from_ctx(gpu_dev, detach_ctx_id,
                                                        resource_id);
                }
                virtio_gpu_unref_resource(gpu_dev, resource_id);
                if (addr) {
                    free_frames(addr, alloc_size / DEFAULT_PAGE_SIZE);
                }
                memset(bo, 0, sizeof(*bo));
                return -ENOSPC;
            }
        }

        bo->bo_handle = bo_handle;
        bo->resource_id = resource_id;
        bo->addr = addr;
        bo->size = req->size;
        bo->alloc_size = alloc_size;
        bo->width = 0;
        bo->height = 0;
        bo->stride = 0;
        bo->format = 0;
        bo->is_blob = true;
        bo->blob_mem = req->blob_mem;
        bo->blob_flags = req->blob_flags;
        bo->blob_id = req->blob_id;
        bo->blob_mapped = false;
        bo->blob_map_info = 0;
        bo->host_visible_offset = 0;
        if (req->cmd_size == 0) {
            bo->attached_ctx_id = create_ctx_id;
        }

        req->bo_handle = bo_handle;
        req->res_handle = resource_id;
        return 0;
    }
    case DRM_IOCTL_VIRTGPU_RESOURCE_INFO: {
        struct drm_virtgpu_resource_info *info = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, info->bo_handle);
        if (!bo || bo->resource_id == 0) {
            return -ENOENT;
        }
        info->res_handle = bo->resource_id;
        info->size = (uint32_t)MIN(bo->size, (uint64_t)UINT32_MAX);
        info->blob_mem = bo->blob_mem;
        return 0;
    }
    case DRM_IOCTL_VIRTGPU_MAP: {
        struct drm_virtgpu_map *map = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, map->handle);
        if (!bo || bo->resource_id == 0) {
            return -ENOENT;
        }
        if (!bo->addr) {
            int ret = virtio_gpu_map_host_visible_blob(gpu_dev, bo);
            if (ret != 0) {
                return ret;
            }
            map->offset =
                gpu_dev->host_visible_shm_paddr + bo->host_visible_offset;
            return 0;
        }
        map->offset = bo->addr;
        return 0;
    }
    case DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST: {
        struct drm_virtgpu_3d_transfer_to_host *req = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, req->bo_handle);
        if (!bo || bo->resource_id == 0) {
            return -ENOENT;
        }
        if (req->box.w == 0) {
            req->box.w = bo->width;
        }
        if (req->box.h == 0) {
            req->box.h = bo->height;
        }
        if (req->box.d == 0) {
            req->box.d = 1;
        }
        return virtio_gpu_transfer_to_host_3d(
            gpu_dev, bo->resource_id, &req->box, req->level, req->offset,
            req->stride, req->layer_stride);
    }
    case DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST: {
        struct drm_virtgpu_3d_transfer_from_host *req = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, req->bo_handle);
        if (!bo || bo->resource_id == 0) {
            return -ENOENT;
        }
        if (req->box.w == 0) {
            req->box.w = bo->width;
        }
        if (req->box.h == 0) {
            req->box.h = bo->height;
        }
        if (req->box.d == 0) {
            req->box.d = 1;
        }
        return virtio_gpu_transfer_from_host_3d(
            gpu_dev, bo->resource_id, &req->box, req->level, req->offset,
            req->stride, req->layer_stride);
    }
    case DRM_IOCTL_VIRTGPU_EXECBUFFER: {
        struct drm_virtgpu_execbuffer *req = arg;
        bool need_fence_fd_in = false;
        bool need_fence_fd_out = false;
        if (!req->command || req->size == 0) {
            return -EINVAL;
        }
        if (req->flags & ~VIRTGPU_EXECBUF_FLAGS) {
            return -EINVAL;
        }
        if (req->flags & VIRTGPU_EXECBUF_FENCE_FD_IN) {
            need_fence_fd_in = true;
        }
        if (req->flags & VIRTGPU_EXECBUF_FENCE_FD_OUT) {
            need_fence_fd_out = true;
        }
        if ((req->flags & VIRTGPU_EXECBUF_RING_IDX) && req->ring_idx != 0) {
            return -EOPNOTSUPP;
        }
        if (!(req->flags & VIRTGPU_EXECBUF_RING_IDX) && req->ring_idx != 0) {
            return -EINVAL;
        }
        if (req->num_in_syncobjs || req->num_out_syncobjs) {
            return -EOPNOTSUPP;
        }
        if (req->size > (1U << 20) ||
            req->num_bo_handles > VIRTIO_GPU_MAX_BOS) {
            return -E2BIG;
        }
        if (req->num_bo_handles && !req->bo_handles) {
            return -EINVAL;
        }
        if (need_fence_fd_in) {
            int ret = virtio_gpu_wait_fence_fd_in(req->fence_fd);
            if (ret != 0) {
                return ret;
            }
        }
        uint32_t capset_id = gpu_dev->active_capset_id
                                 ? gpu_dev->active_capset_id
                                 : VIRTGPU_DRM_CAPSET_VIRGL;
        int ret = virtio_gpu_ensure_context(gpu_dev, capset_id);
        if (ret != 0) {
            return ret;
        }

        uint8_t *command_data = NULL;
        ret = virtio_gpu_copy_from_user_alloc(req->command, req->size,
                                              (void **)&command_data);
        if (ret != 0) {
            return ret;
        }

        uint32_t *bo_handles = NULL;
        if (req->num_bo_handles) {
            uint32_t handles_size = req->num_bo_handles * sizeof(uint32_t);
            ret = virtio_gpu_copy_from_user_alloc(req->bo_handles, handles_size,
                                                  (void **)&bo_handles);
            if (ret != 0) {
                free(command_data);
                return ret;
            }
        }

        if (req->num_bo_handles && req->bo_handles) {
            for (uint32_t i = 0; i < req->num_bo_handles; i++) {
                struct virtio_gpu_bo *bo =
                    virtio_gpu_bo_get(gpu_dev, bo_handles[i]);
                if (!bo || bo->resource_id == 0) {
                    free(bo_handles);
                    free(command_data);
                    return -ENOENT;
                }
                if (bo->attached_ctx_id != gpu_dev->active_ctx_id) {
                    ret = virtio_gpu_attach_resource_to_ctx(
                        gpu_dev, gpu_dev->active_ctx_id, bo->resource_id);
                    if (ret != 0) {
                        free(bo_handles);
                        free(command_data);
                        return ret;
                    }
                    bo->attached_ctx_id = gpu_dev->active_ctx_id;
                }
            }
        }
        free(bo_handles);

        ret = virtio_gpu_submit_3d(gpu_dev, gpu_dev->active_ctx_id,
                                   command_data, req->size);
        free(command_data);
        if (ret == 0 && need_fence_fd_out) {
            int fence_fd = virtio_gpu_create_signaled_fence_fd_out();
            if (fence_fd < 0) {
                return fence_fd;
            }
            req->fence_fd = fence_fd;
        }
        return ret;
    }
    case DRM_IOCTL_VIRTGPU_WAIT: {
        struct drm_virtgpu_3d_wait *req = arg;
        struct virtio_gpu_bo *bo = virtio_gpu_bo_get(gpu_dev, req->handle);
        if (req->flags & ~VIRTGPU_WAIT_NOWAIT) {
            return -EINVAL;
        }
        if (!bo || bo->resource_id == 0) {
            return -ENOENT;
        }
        return 0;
    }
    default:
        return -ENOTTY;
    }
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
    .driver_ioctl = virtio_gpu_driver_ioctl,
};

// Virtio GPU initialization
int virtio_gpu_init(virtio_driver_t *driver) {
    uint64_t supported_features =
        VIRTIO_GPU_F_EDID | VIRTIO_GPU_F_VIRGL | VIRTIO_GPU_F_RESOURCE_BLOB |
        VIRTIO_GPU_F_CONTEXT_INIT | VIRTIO_GPU_F_SUPPORTED_CAPSET_IDS |
        VIRTIO_F_RING_INDIRECT_DESC | VIRTIO_F_RING_EVENT_IDX |
        VIRTIO_F_VERSION_1;
    uint64_t features = virtio_begin_init(driver, supported_features);
    if (!features) {
        printk("virtio_gpu: Failed to negotiate features\n");
        return -1;
    }

    // Create control queue
    virtqueue_t *control_queue =
        virt_queue_new(driver, 0, !!(features & VIRTIO_F_RING_INDIRECT_DESC),
                       !!(features & VIRTIO_F_RING_EVENT_IDX));
    if (!control_queue) {
        printk("virtio_gpu: Failed to create control queue\n");
        return -1;
    }

    virtqueue_t *cursor_queue =
        virt_queue_new(driver, 1, !!(features & VIRTIO_F_RING_INDIRECT_DESC),
                       !!(features & VIRTIO_F_RING_EVENT_IDX));
    if (!cursor_queue) {
        printk("virtio_gpu: Failed to create cursor queue\n");
        return -1;
    }

    virtio_finish_init(driver);

    // Create GPU device structure
    virtio_gpu_device_t *gpu_device = malloc(sizeof(virtio_gpu_device_t));
    memset(gpu_device, 0, sizeof(virtio_gpu_device_t));

    gpu_device->driver = driver;
    gpu_device->control_queue = control_queue;
    gpu_device->cursor_queue = cursor_queue;
    gpu_device->negotiated_features = features;
    gpu_device->virgl_enabled = !!(features & VIRTIO_GPU_F_VIRGL);
    gpu_device->next_resource_id = 1;
    gpu_device->next_bo_handle = 0x10000;
    gpu_device->active_ctx_id = 1;
    gpu_device->lock = SPIN_INIT;
    virtio_pci_device_t *pci = (virtio_pci_device_t *)driver->data;
    if (pci) {
        gpu_device->host_visible_shm_paddr = pci->host_visible_shm_paddr;
        gpu_device->host_visible_shm_size = pci->host_visible_shm_size;
    }

    // Initialize DRM resource manager
    drm_resource_manager_init(&gpu_device->resource_mgr);

    // Get display information
    if (virtio_gpu_get_display_info(gpu_device) <= 0) {
        printk("virtio_gpu: No displays found\n");
        free(gpu_device);
        return -1;
    }

    virtio_gpu_refresh_capset_mask(gpu_device);

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
                gpu_device->planes[i]->format_types[0] = DRM_FORMAT_XRGB8888;
                gpu_device->planes[i]->format_types[1] = DRM_FORMAT_ARGB8888;
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
    gpu_device->drm_dev =
        drm_regist_pci_dev(gpu_device, &virtio_gpu_drm_device_op,
                           ((virtio_pci_device_t *)driver->data)->pci_dev);
    if (!gpu_device->drm_dev) {
        printk("virtio_gpu: Failed to register DRM device\n");
        free(gpu_device);
        return -1;
    }

    drm_device_set_driver_info(gpu_device->drm_dev, "virtio_gpu", "20260222",
                               gpu_device->virgl_enabled
                                   ? "NaOS VirtIO GPU (virgl)"
                                   : "NaOS VirtIO GPU");

    // Add to global device array
    if (virtio_gpu_devices_count < MAX_VIRTIO_GPU_DEVICES) {
        virtio_gpu_devices[virtio_gpu_devices_count++] = gpu_device;
    } else {
        printk("virtio_gpu: Maximum number of GPU devices reached\n");
        free(gpu_device);
        return -1;
    }

    printk("virtio_gpu: Initialized GPU with %d displays%s\n",
           gpu_device->num_displays,
           gpu_device->virgl_enabled ? ", virgl enabled" : "");
    printk("virtio_gpu: drm primary node /dev/dri/card%u\n",
           gpu_device->drm_dev->primary_minor);
    if (gpu_device->host_visible_shm_size) {
        printk("virtio_gpu: host visible shm %#llx + %#llx\n",
               (unsigned long long)gpu_device->host_visible_shm_paddr,
               (unsigned long long)gpu_device->host_visible_shm_size);
    }
    if (gpu_device->drm_dev->render_node_registered) {
        printk("virtio_gpu: render node ready at /dev/dri/renderD%u\n",
               gpu_device->drm_dev->render_minor);
    }

    return 0;
}
