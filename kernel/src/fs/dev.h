#pragma once

#include <fs/vfs/vfs.h>
#include <dev/device.h>
#include <libs/mutex.h>

typedef struct devtmpfs_node {
    char *content;
    uint64_t inode;
    uint64_t dev;
    uint64_t rdev;
    uint64_t blksz;
    uint32_t owner;
    uint32_t group;
    uint32_t type;
    uint16_t mode;
    uint32_t link_count;
    uint32_t handle_refs;
    size_t size;
    size_t capability;
} devtmpfs_node_t;

extern bool devfs_initialized;

void devtmpfs_init();
void devtmpfs_init_umount();

void devfs_register_device(device_t *device);
void devfs_unregister_device(device_t *device);

void input_generate_event(void *data, uint16_t type, uint16_t code,
                          int32_t value, uint64_t sec, uint64_t usecs);

void devfs_nodes_init();

ssize_t inputdev_open(void *data, void *arg);
ssize_t inputdev_close(void *data, void *arg);

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags);
ssize_t inputdev_event_write(void *data, const void *buf, uint64_t offset,
                             uint64_t len, uint64_t flags);
ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd);
ssize_t inputdev_poll(void *data, size_t event);
