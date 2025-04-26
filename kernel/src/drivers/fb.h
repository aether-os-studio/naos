#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

ssize_t fb_read(void *data, uint64_t offset, void *buf, uint64_t len);
ssize_t fb_write(void *data, uint64_t offset, const void *buf, uint64_t len);

void fbdev_init();
