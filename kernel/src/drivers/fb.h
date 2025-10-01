#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>
#include <boot/boot.h>

ssize_t fb_read(void *data, uint64_t offset, void *buf, uint64_t len,
                uint64_t flags);
ssize_t fb_write(void *data, uint64_t offset, const void *buf, uint64_t len,
                 uint64_t flags);
ssize_t fb_ioctl(void *data, ssize_t cmd, ssize_t arg);

void fbdev_init();
void fbdev_init_sysfs();

extern boot_framebuffer_t *framebuffer;

static inline boot_framebuffer_t *get_current_fb() { return framebuffer; }

#define FB_MAJOR 29

#define TTY_CHARACTER_WIDTH 8
#define TTY_CHARACTER_HEIGHT 16
