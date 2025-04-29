#include <drivers/fb.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>
#include <arch/arch.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

ssize_t fb_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    struct limine_framebuffer *fb = (struct limine_framebuffer *)data;
    (void)fb;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

ssize_t fb_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    struct limine_framebuffer *fb = (struct limine_framebuffer *)data;
    memcpy((char *)fb->address + offset, buf, len);
    return len;
}

ssize_t fb_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    struct limine_framebuffer *fb = (struct limine_framebuffer *)data;

    switch (cmd)
    {
    case FB_IOCTL_GETINFO:
        fb_info_t *info_ptr = (fb_info_t *)arg;
        info_ptr->fb_addr = (uint64_t)fb->address;
        info_ptr->width = fb->width;
        info_ptr->height = fb->height;
        info_ptr->bpp = fb->bpp;
        info_ptr->blue_mask_shift = fb->blue_mask_shift;
        info_ptr->blue_mask_size = fb->blue_mask_size;
        info_ptr->green_mask_shift = fb->green_mask_shift;
        info_ptr->green_mask_size = fb->green_mask_size;
        info_ptr->red_mask_shift = fb->red_mask_shift;
        info_ptr->red_mask_size = fb->red_mask_size;
        return 0;

    default:
        return 0;
    }
}

void fbdev_init()
{
    for (uint64_t i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char name[MAX_DEV_NAME_LEN];
        sprintf(name, "fb%d", i);
        regist_dev(name, fb_read, fb_write, fb_ioctl, framebuffer_request.response->framebuffers[i]);
    }
}
