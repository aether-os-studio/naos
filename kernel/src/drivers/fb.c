#include <drivers/fb.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>
#include <arch/arch.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/sys.h>

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
    struct limine_framebuffer *framebuffer = (struct limine_framebuffer *)data;

    switch (cmd)
    {
    case FBIOGET_FSCREENINFO:
        struct fb_fix_screeninfo *fb_fix = (struct fb_fix_screeninfo *)arg;
        memcpy(fb_fix->id, "BIOS", 5);
        fb_fix->smem_start = translate_address(get_current_page_dir(false), (uint64_t)framebuffer->address);
        fb_fix->smem_len = framebuffer->width * framebuffer->height * 4;
        fb_fix->type = FB_TYPE_PACKED_PIXELS;
        fb_fix->type_aux = 0;
        fb_fix->visual = FB_VISUAL_TRUECOLOR;
        fb_fix->xpanstep = 0;
        fb_fix->ypanstep = 0;
        fb_fix->ywrapstep = 0;
        fb_fix->line_length = framebuffer->width * 4;
        fb_fix->mmio_start = translate_address(get_current_page_dir(false), (size_t)framebuffer->address);
        fb_fix->mmio_len = framebuffer->width * framebuffer->height * 4;
        fb_fix->capabilities = 0;
        return 0;
    case FBIOGET_VSCREENINFO:
        struct fb_var_screeninfo *fb_var = (struct fb_var_screeninfo *)arg;
        fb_var->xres = framebuffer->width;
        fb_var->yres = framebuffer->height;

        fb_var->xres_virtual = framebuffer->width;
        fb_var->yres_virtual = framebuffer->height;

        fb_var->red = (struct fb_bitfield){.offset = framebuffer->red_mask_shift,
                                           .length = framebuffer->red_mask_size,
                                           .msb_right = 0};
        fb_var->green =
            (struct fb_bitfield){.offset = framebuffer->green_mask_shift,
                                 .length = framebuffer->green_mask_size,
                                 .msb_right = 0};
        fb_var->blue = (struct fb_bitfield){.offset = framebuffer->blue_mask_shift,
                                            .length = framebuffer->blue_mask_size,
                                            .msb_right = 0};
        fb_var->transp =
            (struct fb_bitfield){.offset = 24, .length = 8, .msb_right = 0};

        fb_var->bits_per_pixel = framebuffer->bpp;
        fb_var->grayscale = 0;
        fb_var->nonstd = 0;
        fb_var->activate = 0;                     // idek
        fb_var->height = framebuffer->height / 4; // VERY approximate
        fb_var->width = framebuffer->width / 4;   // VERY approximate

        return 0;
    case 0x4605: // FBIOPUTCMAP, ignore so no xorg.log spam
        return 0;
    case 0x5413:
        struct winsize *win = (struct winsize *)arg;
        win->ws_row = framebuffer->height / TTY_CHARACTER_HEIGHT;
        win->ws_col = framebuffer->height / TTY_CHARACTER_WIDTH;

        win->ws_xpixel = (uint16_t)framebuffer->width;
        win->ws_ypixel = (uint16_t)framebuffer->height;

        return 0;
    case 0x4601: // FBIOPUT_VSCREENINFO
        struct fb_var_screeninfo *fb_var_user = (struct fb_var_screeninfo *)arg;
        return 0;
    default:
        return (uint64_t)-ENOTTY;
    }
}

void fbdev_init()
{
    for (uint64_t i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char name[MAX_DEV_NAME_LEN];
        sprintf(name, "fb%d", i);
        regist_dev(name, fb_read, fb_write, fb_ioctl, framebuffer_request.response->framebuffers[i]);
        sprintf(name, "dri/card%d", i);
        regist_dev(name, fb_read, fb_write, fb_ioctl, framebuffer_request.response->framebuffers[i]);
    }
}

void fbdev_init_sysfs()
{
    vfs_node_t graphics = vfs_open("/sys/class/graphics");
    for (uint64_t i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char name[MAX_DEV_NAME_LEN];
        sprintf(name, "fb%d", i);
        vfs_node_t node = vfs_child_append(graphics, name, NULL);
        node->type = file_dir;

        vfs_node_t device = vfs_child_append(node, "device", NULL);
        device->type = file_dir;

        vfs_node_t subsystem = vfs_child_append(device, "subsystem", NULL);
        subsystem->type = file_none;
        sysfs_handle_t *subsystem_handle = malloc(sizeof(sysfs_handle_t));
        memset(subsystem_handle, 0, sizeof(sysfs_handle_t));
        subsystem->handle = subsystem_handle;
        sprintf(subsystem_handle->content, "/dev/fb%d", i);
        subsystem->size = strlen(subsystem_handle->content) + 1;

        vfs_node_t uevent = vfs_child_append(node, "uevent", NULL);
        sysfs_handle_t *uevent_handle = malloc(sizeof(sysfs_handle_t));
        memset(subsystem_handle, 0, sizeof(sysfs_handle_t));
        sprintf(uevent_handle->content, "MAJOR=%d\nMINOR=%d\nDEVNAME=/dev/fb%d\n", FB_MAJOR, i, i);
        uevent->handle = uevent_handle;
        uevent->size = strlen(uevent_handle->content) + 1;
    }
}
