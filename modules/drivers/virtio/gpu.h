#pragma once

#include "virtio.h"
#include "queue.h"

#include <drivers/drm/drm.h>
#include <drivers/drm/drm_core.h>

#define VIRTIO_GPU_QUEUE_CONTROL 0
#define VIRTIO_GPU_QUEUE_CURSOR 1

#define VIRTIO_GPU_MAX_SCANOUTS 16
#define VIRTIO_GPU_MAX_DUMB_BUFFERS 4096
#define VIRTIO_GPU_FILE_HANDLE_WORDS ((VIRTIO_GPU_MAX_DUMB_BUFFERS + 63) / 64)
#define VIRTIO_GPU_MAX_CONTEXTS 64
#define VIRTIO_GPU_INVALID_RESOURCE_ID 0

#define VIRTIO_GPU_FLAG_FENCE (1U << 0)
#define VIRTIO_GPU_CONTEXT_INIT_CAPSET_ID_MASK 0x000000ffU

#define VIRTIO_GPU_F_VIRGL (1ULL << 0)
#define VIRTIO_GPU_F_EDID (1ULL << 1)
#define VIRTIO_GPU_F_RESOURCE_UUID (1ULL << 2)
#define VIRTIO_GPU_F_RESOURCE_BLOB (1ULL << 3)
#define VIRTIO_GPU_F_CONTEXT_INIT (1ULL << 4)
#define VIRTIO_GPU_F_SUPPORTED_CAPSET_IDS (1ULL << 5)

#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM 1
#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM 2
#define VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM 3
#define VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM 4
#define VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM 67
#define VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM 68
#define VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM 121
#define VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM 134

typedef enum virtio_gpu_ctrl_type {
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D = 0x0101,
    VIRTIO_GPU_CMD_RESOURCE_UNREF = 0x0102,
    VIRTIO_GPU_CMD_SET_SCANOUT = 0x0103,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH = 0x0104,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D = 0x0105,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING = 0x0106,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING = 0x0107,
    VIRTIO_GPU_CMD_GET_CAPSET_INFO = 0x0108,
    VIRTIO_GPU_CMD_GET_CAPSET = 0x0109,
    VIRTIO_GPU_CMD_GET_EDID = 0x010a,
    VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID = 0x010b,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB = 0x010c,
    VIRTIO_GPU_CMD_SET_SCANOUT_BLOB = 0x010d,

    VIRTIO_GPU_CMD_CTX_CREATE = 0x0200,
    VIRTIO_GPU_CMD_CTX_DESTROY = 0x0201,
    VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE = 0x0202,
    VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE = 0x0203,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_3D = 0x0204,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D = 0x0205,
    VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D = 0x0206,
    VIRTIO_GPU_CMD_SUBMIT_3D = 0x0207,
    VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB = 0x0208,
    VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB = 0x0209,

    VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
    VIRTIO_GPU_RESP_OK_DISPLAY_INFO = 0x1101,
    VIRTIO_GPU_RESP_OK_CAPSET_INFO = 0x1102,
    VIRTIO_GPU_RESP_OK_CAPSET = 0x1103,
    VIRTIO_GPU_RESP_OK_EDID = 0x1104,
    VIRTIO_GPU_RESP_OK_RESOURCE_UUID = 0x1105,
    VIRTIO_GPU_RESP_OK_MAP_INFO = 0x1106,

    VIRTIO_GPU_RESP_ERR_UNSPEC = 0x1200,
    VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY = 0x1201,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID = 0x1202,
    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID = 0x1203,
    VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID = 0x1204,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER = 0x1205,
} virtio_gpu_ctrl_type_t;

typedef struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
} __attribute__((packed)) virtio_gpu_ctrl_hdr_t;

typedef struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed)) virtio_gpu_rect_t;

typedef struct virtio_gpu_display_one {
    virtio_gpu_rect_t rect;
    uint32_t enabled;
    uint32_t flags;
} __attribute__((packed)) virtio_gpu_display_one_t;

typedef struct virtio_gpu_resp_display_info {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_display_one_t pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __attribute__((packed)) virtio_gpu_resp_display_info_t;

typedef struct virtio_gpu_resource_create_2d {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed)) virtio_gpu_resource_create_2d_t;

typedef struct virtio_gpu_resource_unref {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resource_unref_t;

typedef struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_mem_entry_t;

typedef struct virtio_gpu_resource_attach_backing {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
} __attribute__((packed)) virtio_gpu_resource_attach_backing_t;

typedef struct virtio_gpu_resource_detach_backing {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resource_detach_backing_t;

typedef struct virtio_gpu_set_scanout {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed)) virtio_gpu_set_scanout_t;

typedef struct virtio_gpu_transfer_to_host_2d {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_transfer_to_host_2d_t;

typedef struct virtio_gpu_resource_flush {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resource_flush_t;

typedef struct virtio_gpu_box {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
    uint32_t h;
    uint32_t d;
} __attribute__((packed)) virtio_gpu_box_t;

typedef struct virtio_gpu_transfer_host_3d {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_box_t box;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t level;
    uint32_t stride;
    uint32_t layer_stride;
} __attribute__((packed)) virtio_gpu_transfer_host_3d_t;

typedef struct virtio_gpu_resource_create_3d {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t target;
    uint32_t format;
    uint32_t bind;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t array_size;
    uint32_t last_level;
    uint32_t nr_samples;
    uint32_t flags;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resource_create_3d_t;

typedef struct virtio_gpu_ctx_create {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t nlen;
    uint32_t context_init;
    char debug_name[64];
} __attribute__((packed)) virtio_gpu_ctx_create_t;

typedef struct virtio_gpu_ctx_destroy {
    virtio_gpu_ctrl_hdr_t hdr;
} __attribute__((packed)) virtio_gpu_ctx_destroy_t;

typedef struct virtio_gpu_ctx_resource {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_ctx_resource_t;

typedef struct virtio_gpu_cmd_submit {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t size;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_cmd_submit_t;

typedef struct virtio_gpu_get_capset_info {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t capset_index;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_get_capset_info_t;

typedef struct virtio_gpu_resp_capset_info {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t capset_id;
    uint32_t capset_max_version;
    uint32_t capset_max_size;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resp_capset_info_t;

typedef struct virtio_gpu_get_capset {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t capset_id;
    uint32_t capset_version;
} __attribute__((packed)) virtio_gpu_get_capset_t;

typedef enum virtio_gpu_object_kind {
    VIRTIO_GPU_OBJECT_DUMB_2D,
    VIRTIO_GPU_OBJECT_PRIVATE_3D,
    VIRTIO_GPU_OBJECT_BLOB,
} virtio_gpu_object_kind_t;

typedef struct virtio_gpu_buffer {
    bool used;
    virtio_gpu_object_kind_t kind;
    uint32_t handle;
    uint32_t resource_id;
    uint64_t paddr;
    uint64_t size;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
    int refcount;
    uint64_t attached_context_mask;
} virtio_gpu_buffer_t;

typedef struct virtio_gpu_context {
    bool used;
    uint32_t id;
    uint32_t capset_id;
    char debug_name[64];
} virtio_gpu_context_t;

typedef struct virtio_gpu_file {
    uint32_t ctx_id;
    uint32_t capset_id;
    uint64_t handles[VIRTIO_GPU_FILE_HANDLE_WORDS];
} virtio_gpu_file_t;

typedef struct virtio_gpu_device {
    virtio_driver_t *driver;
    virtqueue_t *control_vq;
    virtqueue_t *cursor_vq;
    spinlock_t control_lock;
    uint64_t negotiated_features;
    uint32_t num_capsets;
    uint32_t next_resource_id;
    uint32_t next_context_id;
    uint64_t supported_capset_ids;
    uint32_t scanout_id;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    bool display_valid;

    virtio_gpu_buffer_t buffers[VIRTIO_GPU_MAX_DUMB_BUFFERS];
    virtio_gpu_context_t contexts[VIRTIO_GPU_MAX_CONTEXTS];

    drm_connector_t *connectors[DRM_MAX_CONNECTORS_PER_DEVICE];
    drm_crtc_t *crtcs[DRM_MAX_CRTCS_PER_DEVICE];
    drm_encoder_t *encoders[DRM_MAX_ENCODERS_PER_DEVICE];
    drm_resource_manager_t resource_mgr;
    drm_device_t *drm_dev;
} virtio_gpu_device_t;

int virtio_gpu_init(virtio_driver_t *driver);
