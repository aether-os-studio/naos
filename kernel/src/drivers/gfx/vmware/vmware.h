#pragma once

#include <libs/klibc.h>
#include <drivers/drm/drm.h>

#define VMWARE_GPU_VERSION_MAGIC 0x900000
#define VMWARE_GPU_VERSION_ID_2 ((VMWARE_GPU_VERSION_MAGIC << 8) | 2)
#define VMWARE_GPU_VERSION_ID_1 ((VMWARE_GPU_VERSION_MAGIC << 8) | 1)
#define VMWARE_GPU_VERSION_ID_0 ((VMWARE_GPU_VERSION_MAGIC << 8) | 0)

enum register_index
{
    register_index_id = 0,
    register_index_enable = 1,
    register_index_width = 2,
    register_index_height = 3,
    register_index_max_width = 4,
    register_index_max_height = 5,
    register_index_depth = 6,
    register_index_bits_per_pixel = 7,
    register_index_pseudocolor = 8,
    register_index_red_mask = 9,
    register_index_green_mask = 10,
    register_index_blue_mask = 11,
    register_index_bytes_per_line = 12,
    register_index_fb_start = 13,
    register_index_fb_offset = 14,
    register_index_vram_size = 15,
    register_index_fb_size = 16,

    register_index_capabilities = 17,
    register_index_mem_start = 18,
    register_index_mem_size = 19,
    register_index_config_done = 20,
    register_index_sync = 21,
    register_index_busy = 22,
    register_index_guest_id = 23,
    register_index_cursor_id = 24,
    register_index_cursor_x = 25,
    register_index_cursor_y = 26,
    register_index_cursor_on = 27,
    register_index_host_bits_per_pixel = 28,
    register_index_scratch_size = 29,
    register_index_mem_regs = 30,
    register_index_num_displays = 31,
    register_index_pitchlock = 32,
    register_index_irqmask = 33,

    register_index_num_guest_displays = 34,
    register_index_display_id = 35,
    register_index_display_is_primary = 36,
    register_index_display_position_x = 37,
    register_index_display_position_y = 38,
    register_index_display_width = 39,
    register_index_display_height = 40,

    register_index_gmr_id = 41,
    register_index_gmr_descriptor = 42,
    register_index_gmr_max_ids = 43,
    register_index_gmr_max_descriptor_length = 44,

    register_index_traces = 45,
    register_index_gmrs_max_pages = 46,
    register_index_memory_size = 47,
    register_index_top = 48,
};

enum command_index
{
    command_index_invalid_cmd = 0,
    command_index_update = 1,
    command_index_rect_copy = 3,
    command_index_define_cursor = 19,
    command_index_define_alpha_cursor = 22,
    command_index_update_verbose = 25,
    command_index_front_rop_fill = 29,
    command_index_fence = 30,
    command_index_escape = 33,
    command_index_define_screen = 34,
    command_index_destroy_screen = 35,
    command_index_define_gmrfb = 36,
    command_index_blit_gmrfb_to_screen = 37,
    command_index_blit_screen_to_gmrfb = 38,
    command_index_annotation_fill = 39,
    command_index_annotation_copy = 40,
    command_index_define_gmr2 = 41,
    command_index_remap_gmr2 = 42,
    command_index_max
};

enum fifo_index
{
    fifo_index_min = 0,
    fifo_index_max,
    fifo_index_next_cmd,
    fifo_index_stop,

    fifo_index_capabilities = 4,
    fifo_index_flags,
    fifo_index_fence,

    fifo_index_3d_hwversion,
    fifo_index_pitchlock,

    fifo_index_cursor_on,
    fifo_index_cursor_x,
    fifo_index_cursor_y,
    fifo_index_cursor_count,
    fifo_index_cursor_last_updated,

    fifo_index_reserved,

    fifo_index_cursor_screen_id,

    fifo_index_dead,

    fifo_index_3d_hwversion_revised,

    fifo_index_3d_caps = 32,
    fifo_index_3d_caps_last = 32 + 255,

    fifo_index_guest_3d_hwversion,
    fifo_index_fence_goal,
    fifo_index_busy,

    fifo_index_num_regs
};

// only necessary commands are implemented
struct vmware_gpu_define_alpha_cursor
{
    uint32_t id; // must be 0
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    uint32_t width;
    uint32_t height;
    uint8_t pixel_data[];
};

struct vmware_gpu_define_cursor
{
    uint32_t id; // must be 0
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    uint32_t width;
    uint32_t height;
    uint32_t and_mask_depth;
    uint32_t xor_mask_depth;
    uint8_t pixel_data[];
};

struct vmware_gpu_update_rectangle
{
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
};

struct vmware_gpu_copy_rectangle
{
    uint32_t sx;
    uint32_t sy;
    uint32_t dx;
    uint32_t dy;
    uint32_t w;
    uint32_t h;
};

enum caps
{
    cap_cursor = 0x00000020,
    cap_fifo_extended = 0x00008000,
    cap_irqmask = 0x00040000,
    cap_fifo_reserve = (1 << 6),
    cap_fifo_cursor_bypass_3 = (1 << 4),
};

#define MAX_VMWARE_GPU_DEVICE_NUM 8

typedef struct vmware_gpu_fb
{
    uint64_t addr;
    uint64_t width;
    uint64_t height;
} vmware_gpu_fb_t;

typedef struct vmware_gpu_device
{
    uint16_t io_base;
    uint64_t fb_mmio_base;
    uint64_t fifo_mmio_base;

    uint32_t current_w;
    uint32_t current_h;

    uint32_t version;
    uint32_t fifo_size;

    uint32_t caps;

    vmware_gpu_fb_t *fbs[MAX_FB_NUM];
} vmware_gpu_device_t;

extern vmware_gpu_device_t *vmware_gpu_devices[MAX_VMWARE_GPU_DEVICE_NUM];
extern uint32_t vmware_gpu_devices_count;

extern drm_device_op_t vmware_drm_device_op;

void vmware_gpu_init();
