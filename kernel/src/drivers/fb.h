#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

ssize_t fb_read(void *data, uint64_t offset, void *buf, uint64_t len);
ssize_t fb_write(void *data, uint64_t offset, const void *buf, uint64_t len);
ssize_t fb_ioctl(void *data, ssize_t cmd, ssize_t arg);

void fbdev_init();
void fbdev_init_sysfs();

extern volatile struct limine_framebuffer_request framebuffer_request;

struct drm_version
{
    int version_major;      /**< Major version */
    int version_minor;      /**< Minor version */
    int version_patchlevel; /**< Patch level */
    size_t name_len;        /**< Length of name buffer */
    char *name;             /**< Name of driver */
    size_t date_len;        /**< Length of date buffer */
    char *date;             /**< User-space buffer to hold date */
    size_t desc_len;        /**< Length of desc buffer */
    char *desc;             /**< User-space buffer to hold desc */
};

#define FB_MAJOR 29

#define TTY_CHARACTER_WIDTH 8
#define TTY_CHARACTER_HEIGHT 16
