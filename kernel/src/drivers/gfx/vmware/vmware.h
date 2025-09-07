#pragma once

#include <libs/klibc.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm_mode.h>

#define VMWARE_GPU_VERSION_MAGIC 0x900000
#define VMWARE_GPU_VERSION_ID_2 ((VMWARE_GPU_VERSION_MAGIC << 8) | 2)
#define VMWARE_GPU_VERSION_ID_1 ((VMWARE_GPU_VERSION_MAGIC << 8) | 1)
#define VMWARE_GPU_VERSION_ID_0 ((VMWARE_GPU_VERSION_MAGIC << 8) | 0)

// Maximum number of displays supported by VMware SVGA II
#define VMWARE_MAX_DISPLAYS 16
#define VMWARE_MAX_FRAMEBUFFERS 32
#define VMWARE_CURSOR_WIDTH 64
#define VMWARE_CURSOR_HEIGHT 64

// Register indices
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

// Command indices
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

// FIFO indices
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

// Capabilities
enum caps
{
    cap_cursor = 0x00000020,
    cap_fifo_extended = 0x00008000,
    cap_irqmask = 0x00040000,
    cap_gmr = 0x00080000,
    cap_gmr2 = 0x00100000,
    cap_3d = 0x00020000,
    cap_fifo_reserve = (1 << 6),
    cap_fifo_cursor_bypass_3 = (1 << 4),
};

// IRQ masks
enum irq_masks
{
    irq_mask_any = 0xFFFFFFFF,
    irq_mask_fence = 0x00000001,
    irq_mask_flip = 0x00000002,
    irq_mask_cursor = 0x00000004,
};

// Display information structure
typedef struct vmware_display_info
{
    uint32_t id;
    uint32_t is_primary;
    uint32_t position_x;
    uint32_t position_y;
    uint32_t width;
    uint32_t height;
    uint32_t enabled;
} vmware_display_info_t;

// Framebuffer structure
typedef struct vmware_framebuffer
{
    int fb_id;
    uint64_t addr;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t format;
    uint32_t refcount;
} vmware_framebuffer_t;

// Cursor structure
typedef struct vmware_cursor
{
    uint32_t width;
    uint32_t height;
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    uint32_t *pixels;
    uint32_t refcount;
} vmware_cursor_t;

// Main device structure
typedef struct vmware_gpu_device
{
    uint16_t io_base;
    uint64_t fb_mmio_base;
    uint64_t fifo_mmio_base;

    uint32_t version;
    uint32_t fifo_size;
    uint32_t caps;
    uint32_t vram_size;

    // Display information
    uint32_t num_displays;
    vmware_display_info_t displays[VMWARE_MAX_DISPLAYS];

    // Framebuffer management
    vmware_framebuffer_t *framebuffers[VMWARE_MAX_FRAMEBUFFERS];
    uint32_t next_fb_id;

    // Cursor management
    vmware_cursor_t *cursor;

    // DRM resources
    drm_connector_t *connectors[VMWARE_MAX_DISPLAYS];
    drm_crtc_t *crtcs[VMWARE_MAX_DISPLAYS];
    drm_encoder_t *encoders[VMWARE_MAX_DISPLAYS];

    // Synchronization
    spinlock_t lock;
    uint32_t fence_seq;

    // Interrupt handling
    uint32_t irq_mask;
    uint32_t pending_irqs;

    drm_resource_manager_t resource_mgr;
} vmware_gpu_device_t;

// Command structures
struct vmware_gpu_define_alpha_cursor
{
    uint32_t id;
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    uint32_t width;
    uint32_t height;
    uint8_t pixel_data[];
};

struct vmware_gpu_define_cursor
{
    uint32_t id;
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

struct vmware_gpu_fence
{
    uint32_t sequence;
};

// Global device array
#define MAX_VMWARE_GPU_DEVICES 8
extern vmware_gpu_device_t *vmware_gpu_devices[MAX_VMWARE_GPU_DEVICES];
extern uint32_t vmware_gpu_devices_count;

// DRM device operations
extern drm_device_op_t vmware_drm_device_op;

// Function prototypes
void vmware_gpu_init();
void vmware_gpu_irq_handler(vmware_gpu_device_t *device);
int vmware_gpu_detect_displays(vmware_gpu_device_t *device);
int vmware_gpu_set_display_mode(vmware_gpu_device_t *device, uint32_t display_id,
                                uint32_t width, uint32_t height, uint32_t bpp);
int vmware_gpu_update_display(vmware_gpu_device_t *device, uint32_t display_id,
                              uint32_t x, uint32_t y, uint32_t w, uint32_t h);
int vmware_gpu_set_cursor(vmware_gpu_device_t *device, uint32_t display_id,
                          vmware_cursor_t *cursor, uint32_t x, uint32_t y);
int vmware_gpu_move_cursor(vmware_gpu_device_t *device, uint32_t display_id,
                           uint32_t x, uint32_t y);

// Utility functions
static inline uint32_t vmware_read_register(vmware_gpu_device_t *device, uint32_t index);
static inline void vmware_write_register(vmware_gpu_device_t *device, uint32_t index, uint32_t value);
static inline uint32_t vmware_fifo_read(vmware_gpu_device_t *device, uint32_t index);
static inline void vmware_fifo_write(vmware_gpu_device_t *device, uint32_t index, uint32_t value);
static inline bool vmware_has_capability(vmware_gpu_device_t *device, enum caps capability);
void *vmware_fifo_reserve(vmware_gpu_device_t *device, size_t size);
void vmware_fifo_commit(vmware_gpu_device_t *device, size_t bytes);
int vmware_wait_fence(vmware_gpu_device_t *device, uint32_t sequence);
