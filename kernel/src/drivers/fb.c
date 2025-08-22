#include <drivers/fb.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>
#include <arch/arch.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/sys.h>

__attribute__((used, section(".limine_requests"))) volatile struct limine_framebuffer_request framebuffer_request = {.id = LIMINE_FRAMEBUFFER_REQUEST, .revision = 0};

struct limine_framebuffer *framebuffer = NULL;

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

    cmd = cmd & 0xFFFFFFFF;

    switch (cmd)
    {
    case FBIOGET_FSCREENINFO:
        struct fb_fix_screeninfo *fb_fix = (struct fb_fix_screeninfo *)arg;
        memcpy(fb_fix->id, "NAOS-FBDEV", 10);
        fb_fix->smem_start = translate_address(get_current_page_dir(false), (uint64_t)framebuffer->address);
        fb_fix->smem_len = framebuffer->pitch * framebuffer->height;
        fb_fix->type = FB_TYPE_PACKED_PIXELS;
        fb_fix->type_aux = 0;
        fb_fix->visual = FB_VISUAL_TRUECOLOR;
        fb_fix->xpanstep = 0;
        fb_fix->ypanstep = 0;
        fb_fix->ywrapstep = 0;
        fb_fix->line_length = framebuffer->pitch;
        fb_fix->mmio_start = translate_address(get_current_page_dir(false), (size_t)framebuffer->address);
        fb_fix->mmio_len = framebuffer->pitch * framebuffer->height;
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
        fb_var->green = (struct fb_bitfield){.offset = framebuffer->green_mask_shift,
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
        size_t col, row;
        get_terminal_col_rows(&col, &row);

        struct winsize *win = (struct winsize *)arg;
        win->ws_col = col;
        win->ws_row = row;

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

void *fb_map(void *data, void *addr, uint64_t offset, uint64_t len)
{
    struct limine_framebuffer *framebuffer = (struct limine_framebuffer *)data;

    uint64_t fb_addr = translate_address(get_current_page_dir(false), (uint64_t)framebuffer->address) + offset;

    map_page_range(get_current_page_dir(true), (uint64_t)addr, (uint64_t)fb_addr, framebuffer->width * framebuffer->height * framebuffer->bpp / 8, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

void fbdev_init()
{
    char name[MAX_DEV_NAME_LEN];
    sprintf(name, "fb%d", 0);
    regist_dev(name, fb_read, fb_write, fb_ioctl, NULL, fb_map, framebuffer);
}

void fbdev_init_sysfs()
{
    vfs_node_t graphics = vfs_open("/sys/class/graphics");

    char name[MAX_DEV_NAME_LEN];
    sprintf(name, "fb%d", 0);
    vfs_node_t node = sysfs_child_append(graphics, name, true);

    vfs_node_t modes = sysfs_child_append(node, "modes", false);
    char content[64];
    sprintf(content, "U:%dx%d\n", framebuffer->width, framebuffer->height);
    vfs_write(modes, content, 0, strlen(content));

    vfs_node_t device = sysfs_child_append(node, "device", true);
    vfs_node_t subsystem = sysfs_child_append_symlink(device, "subsystem", "/sys/class/graphics");
    vfs_node_t uevent = sysfs_child_append(device, "uevent", false);
    sprintf(content, "MAJOR=%d\nMINOR=%d\nDEVNAME=fb%d\nSUBSYSTEM=graphics\n", 29, 0, 0);
    vfs_write(uevent, content, 0, strlen(content));

    char *subsystem_fullpath = vfs_get_fullpath(subsystem);
    vfs_node_t subsystem_link = sysfs_child_append_symlink(node, "subsystem", subsystem_fullpath);
    free(subsystem_fullpath);

    char *uevent_fullpath = vfs_get_fullpath(uevent);
    vfs_node_t uevent_link = sysfs_child_append_symlink(node, "uevent", uevent_fullpath);
    free(uevent_fullpath);
}
