#include <mm/hhdm.h>
#include <drivers/gfx/simple.h>

static int simple_get_display_info(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp)
{
    struct limine_framebuffer *fb = dev_data;

    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;

    return 0;
}

static int simple_get_fb(void *dev_data, uint32_t *width, uint32_t *height, uint32_t *bpp, uint64_t *addr)
{
    struct limine_framebuffer *fb = dev_data;

    *width = fb->width;
    *height = fb->height;
    *bpp = fb->bpp;
    *addr = virt_to_phys((uint64_t)fb->address);

    return 0;
}

int simple_create_dumb(void *dev_data, struct drm_mode_create_dumb *create)
{
    struct limine_framebuffer *fb = dev_data;

    create->height = fb->height;
    create->width = fb->width;
    create->bpp = fb->bpp;
    create->pitch = fb->pitch;
    create->size = create->pitch * create->height;
    create->handle = 1;

    return 0;
}

int simple_destroy_dumb(void *dev_data, uint32_t handle)
{
    return 0;
}

int simple_dirty_fb(void *dev_data, struct drm_mode_fb_dirty_cmd *cmd)
{
    return 0;
}

int simple_map_dumb(void *dev_data, struct drm_mode_map_dumb *map)
{
    struct limine_framebuffer *fb = dev_data;

    map->offset = virt_to_phys((uint64_t)fb->address);

    return 0;
}

int simple_page_flip(drm_device_t *dev, struct drm_mode_crtc_page_flip *flip)
{
    if (flip->crtc_id != 1)
        return -ENOENT;

    for (int i = 0; i < DRM_MAX_EVENTS_COUNT; i++)
    {
        if (!dev->drm_events[i])
        {
            dev->drm_events[i] = malloc(sizeof(struct k_drm_event));
            dev->drm_events[i]->type = DRM_EVENT_FLIP_COMPLETE;
            dev->drm_events[i]->user_data = flip->user_data;
            dev->drm_events[i]->timestamp.tv_sec = nanoTime() / 1000000000ULL;
            dev->drm_events[i]->timestamp.tv_nsec = nanoTime() % 1000000000ULL;
            break;
        }
    }

    return 0;
}

int simple_set_crtc(void *dev_data, struct drm_mode_crtc *crtc)
{
    return 0;
}

drm_device_op_t simple_drm_ops = {
    .set_crtc = simple_set_crtc,
    .get_display_info = simple_get_display_info,
    .get_fb = simple_get_fb,
    .create_dumb = simple_create_dumb,
    .destroy_dumb = simple_destroy_dumb,
    .dirty_fb = simple_dirty_fb,
    .map_dumb = simple_map_dumb,
    .page_flip = simple_page_flip,
};
