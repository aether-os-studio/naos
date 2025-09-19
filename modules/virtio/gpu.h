#pragma once

#include "virtio.h"
#include "queue.h"
#include <libs/aether/drm.h>
#include <libs/aether/mm.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm_mode.h>

// Virtio GPU features
#define VIRTIO_GPU_F_VIRGL (1 << 0)
#define VIRTIO_GPU_F_EDID (1 << 1)

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

    // Display information
    uint32_t num_displays;
    virtio_gpu_display_one_t displays[16];

    // Resource management
    uint32_t next_resource_id;

    // DRM resources
    drm_connector_t *connectors[16];
    drm_crtc_t *crtcs[16];
    drm_encoder_t *encoders[16];
    drm_resource_manager_t resource_mgr;

    // Framebuffer management
    struct virtio_gpu_framebuffer {
        uint32_t resource_id;
        uint64_t addr;
        uint32_t width;
        uint32_t height;
        uint32_t pitch;
        uint32_t format;
        uint32_t refcount;
    } framebuffers[32];

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
