#pragma once

#include <fs/vfs/vfs.h>
#include <dev/device.h>
#include <libs/mutex.h>

typedef struct devtmpfs_node {
    vfs_node_t node;
    // for file type
    char *content;
    int size;
    int capability;
} devtmpfs_node_t;

extern bool devfs_initialized;

void devtmpfs_init();
void devtmpfs_init_umount();

void devfs_register_device(device_t *device);

void input_generate_event(dev_input_event_t *item, uint16_t type, uint16_t code,
                          int32_t value, uint64_t sec, uint64_t usecs);

void devfs_nodes_init();

ssize_t inputdev_open(void *data, void *arg);
ssize_t inputdev_close(void *data, void *arg);

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags);
ssize_t inputdev_event_write(void *data, const void *buf, uint64_t offset,
                             uint64_t len, uint64_t flags);
ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg);
ssize_t inputdev_poll(void *data, size_t event);
