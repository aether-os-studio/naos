#pragma once

#include "virtio.h"
#include "queue.h"
#include <libs/aether/drm.h>
#include <libs/aether/mm.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm_mode.h>

// Virtio GPU features
#define VIRTIO_GPU_F_VIRGL (1ULL << 0)
#define VIRTIO_GPU_F_EDID (1ULL << 1)
#define VIRTIO_GPU_F_RESOURCE_UUID (1ULL << 2)
#define VIRTIO_GPU_F_RESOURCE_BLOB (1ULL << 3)
#define VIRTIO_GPU_F_CONTEXT_INIT (1ULL << 4)
#define VIRTIO_GPU_F_SUPPORTED_CAPSET_IDS (1ULL << 5)
#define VIRTIO_GPU_MAX_BOS 256
#define VIRTIO_GPU_FLAG_FENCE 0x1

// Virtio GPU request types
typedef enum virtio_gpu_ctrl_type {
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    VIRTIO_GPU_CMD_RESOURCE_UNREF,
    VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_GET_CAPSET_INFO,
    VIRTIO_GPU_CMD_GET_CAPSET,
    VIRTIO_GPU_CMD_GET_EDID,
    VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
    VIRTIO_GPU_CMD_SET_SCANOUT_BLOB,
    VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB,
    VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB,
    VIRTIO_GPU_CMD_CTX_CREATE = 0x0200,
    VIRTIO_GPU_CMD_CTX_DESTROY,
    VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
    VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
    VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
    VIRTIO_GPU_CMD_SUBMIT_3D,
    VIRTIO_GPU_CMD_UPDATE_CURSOR = 0x0300,
    VIRTIO_GPU_CMD_MOVE_CURSOR,
} virtio_gpu_ctrl_type_t;

// Virtio GPU response types
typedef enum virtio_gpu_resp_type {
    VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
    VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET,
    VIRTIO_GPU_RESP_OK_EDID,
    VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
    VIRTIO_GPU_RESP_OK_MAP_INFO,
    VIRTIO_GPU_RESP_ERR_UNSPEC,
    VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
} virtio_gpu_resp_type_t;

// Virtio GPU formats
typedef enum virtio_gpu_formats {
    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM = 1,
    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM = 2,
    VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM = 3,
    VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM = 4,
    VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM = 67,
    VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM = 68,
    VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM = 121,
    VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM = 134,
} virtio_gpu_formats_t;

struct virtio_gpu_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

typedef struct virtio_gpu_box {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
    uint32_t h;
    uint32_t d;
} virtio_gpu_box_t;

// Virtio GPU display information
typedef struct virtio_gpu_display_one {
    struct virtio_gpu_rect rect;
    uint32_t enabled;
    uint32_t flags;
} virtio_gpu_display_one_t;

// Virtio GPU control header
typedef struct virtio_gpu_ctrl_hdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} virtio_gpu_ctrl_hdr_t;

typedef struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    virtio_gpu_display_one_t displays[16];
} virtio_gpu_resp_display_info_t;

#define RESOURCE_ID_FB 0xbabe
#define RESOURCE_ID_CURSOR 0xdade

// Virtio GPU 2D resource creation
typedef struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} virtio_gpu_resource_create_2d_t;

typedef struct virtio_gpu_resource_create_3d {
    struct virtio_gpu_ctrl_hdr hdr;
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
} virtio_gpu_resource_create_3d_t;

// Virtio GPU set scanout
typedef struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
} virtio_gpu_set_scanout_t;

// Virtio GPU transfer to host
typedef struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_transfer_to_host_2d_t;

// Virtio GPU resource flush
typedef struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_flush_t;

// Virtio GPU attach backing
typedef struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} virtio_gpu_mem_entry_t;

typedef struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    virtio_gpu_mem_entry_t mem_entry;
} virtio_gpu_resource_attach_backing_t;

typedef struct virtio_gpu_ctx_create {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t nlen;
    uint32_t context_init;
    uint8_t debug_name[64];
} virtio_gpu_ctx_create_t;

typedef struct virtio_gpu_ctx_destroy {
    struct virtio_gpu_ctrl_hdr hdr;
} virtio_gpu_ctx_destroy_t;

typedef struct virtio_gpu_ctx_resource {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_ctx_resource_t;

typedef struct virtio_gpu_cmd_submit {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t size;
    uint32_t padding;
    uint8_t data[];
} virtio_gpu_cmd_submit_t;

typedef struct virtio_gpu_get_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_index;
    uint32_t padding;
} virtio_gpu_get_capset_info_t;

typedef struct virtio_gpu_resp_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_max_version;
    uint32_t capset_max_size;
    uint32_t padding;
} virtio_gpu_resp_capset_info_t;

typedef struct virtio_gpu_get_capset {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_version;
} virtio_gpu_get_capset_t;

typedef struct virtio_gpu_resource_create_blob {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t blob_mem;
    uint32_t blob_flags;
    uint32_t nr_entries;
    uint64_t blob_id;
    uint64_t size;
    virtio_gpu_mem_entry_t mem_entry;
} virtio_gpu_resource_create_blob_t;

typedef struct virtio_gpu_transfer_host_3d {
    struct virtio_gpu_ctrl_hdr hdr;
    virtio_gpu_box_t box;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t level;
    uint32_t stride;
    uint32_t layer_stride;
} virtio_gpu_transfer_host_3d_t;

typedef struct virtio_gpu_resource_map_blob {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
    uint64_t offset;
} virtio_gpu_resource_map_blob_t;

typedef struct virtio_gpu_resource_unmap_blob {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_unmap_blob_t;

typedef struct virtio_gpu_resp_map_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t map_info;
    uint32_t padding;
} virtio_gpu_resp_map_info_t;

typedef struct virtio_gpu_resource_detach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_detach_backing_t;

typedef struct virtio_gpu_resource_unref {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_unref_t;

// Virtio GPU cursor update
typedef struct virtio_gpu_update_cursor {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t pos_x;
    uint32_t pos_y;
    uint32_t hot_x;
    uint32_t hot_y;
    uint32_t padding;
    uint32_t resource_id;
} virtio_gpu_update_cursor_t;

// Virtio GPU cursor move
typedef struct virtio_gpu_move_cursor {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t pos_x;
    uint32_t pos_y;
    uint32_t padding;
    uint32_t resource_id;
} virtio_gpu_move_cursor_t;

// Virtio GPU device structure
typedef struct virtio_gpu_device {
    virtio_driver_t *driver;
    virtqueue_t *control_queue;
    virtqueue_t *cursor_queue;
    drm_device_t *drm_dev;

    uint64_t negotiated_features;
    bool virgl_enabled;

    // Display information
    uint32_t num_displays;
    virtio_gpu_display_one_t displays[16];
    uint32_t scanout_ids[16];

    // Resource management
    uint32_t next_resource_id;

    // DRM resources
    drm_connector_t *connectors[16];
    drm_crtc_t *crtcs[16];
    drm_encoder_t *encoders[16];
    drm_plane_t *planes[16];
    drm_resource_manager_t resource_mgr;

    // Framebuffer management
    struct virtio_gpu_framebuffer {
        uint32_t resource_id;
        uint64_t addr;
        uint32_t width;
        uint32_t height;
        uint32_t pitch;
        uint32_t format;
        uint64_t size;
        uint32_t refcount;
    } framebuffers[32];

    struct virtio_gpu_bo {
        bool in_use;
        uint32_t bo_handle;
        uint32_t resource_id;
        uint64_t addr;
        uint64_t size;
        uint64_t alloc_size;
        uint32_t width;
        uint32_t height;
        uint32_t stride;
        uint32_t format;
        bool is_blob;
        uint32_t blob_mem;
        uint32_t blob_flags;
        uint64_t blob_id;
        bool blob_mapped;
        uint32_t blob_map_info;
        uint64_t host_visible_offset;
        uint32_t attached_ctx_id;
    } bos[VIRTIO_GPU_MAX_BOS];

    uint32_t next_bo_handle;
    uint32_t active_ctx_id;
    uint32_t active_capset_id;
    bool context_initialized;
    uint64_t supported_capset_mask;
    uint64_t host_visible_shm_paddr;
    uint64_t host_visible_shm_size;

    // Synchronization
    spinlock_t lock;
    uint64_t fence_seq;
} virtio_gpu_device_t;

// Maximum number of GPU devices
#define MAX_VIRTIO_GPU_DEVICES 8

// Global device array
extern virtio_gpu_device_t *virtio_gpu_devices[MAX_VIRTIO_GPU_DEVICES];
extern uint32_t virtio_gpu_devices_count;

// Function declarations
int virtio_gpu_init(virtio_driver_t *driver);
int virtio_gpu_get_display_info(virtio_gpu_device_t *gpu_dev);
int virtio_gpu_create_resource(virtio_gpu_device_t *gpu_dev,
                               uint32_t resource_id, uint32_t format,
                               uint32_t width, uint32_t height);
int virtio_gpu_attach_backing(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id, uint64_t addr,
                              uint32_t length);
int virtio_gpu_detach_backing(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id);
int virtio_gpu_unref_resource(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id);
int virtio_gpu_set_scanout(virtio_gpu_device_t *gpu_dev, uint32_t scanout_id,
                           uint32_t resource_id, uint32_t width,
                           uint32_t height, uint32_t x, uint32_t y);
int virtio_gpu_transfer_to_host(virtio_gpu_device_t *gpu_dev,
                                uint32_t resource_id, uint32_t width,
                                uint32_t height, uint32_t x, uint32_t y);
int virtio_gpu_resource_flush(virtio_gpu_device_t *gpu_dev,
                              uint32_t resource_id, uint32_t width,
                              uint32_t height, uint32_t x, uint32_t y);
int virtio_gpu_update_cursor(virtio_gpu_device_t *gpu_dev, uint32_t resource_id,
                             uint32_t pos_x, uint32_t pos_y, uint32_t hot_x,
                             uint32_t hot_y);
int virtio_gpu_move_cursor(virtio_gpu_device_t *gpu_dev, uint32_t resource_id,
                           uint32_t pos_x, uint32_t pos_y);

// DRM device operations
extern drm_device_op_t virtio_gpu_drm_device_op;
