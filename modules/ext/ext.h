#pragma once

#include <fs/vfs/vfs.h>
#include <lwext4/blockdev/device_dev.h>
#include <lwext4/include/ext4_types.h>
#include <lwext4/include/ext4.h>

typedef struct ext_handle {
    vfs_node_t node;
    union {
        ext4_file *file;
        ext4_dir *dir;
        void *ptr;
    };
} ext_handle_t;

int ext_mount(uint64_t dev, vfs_node_t node);
void ext_unmount(vfs_node_t node);
void ext_open(vfs_node_t parent, const char *name, vfs_node_t node);
bool ext_close(vfs_node_t node);
ssize_t ext_write(fd_t *file, const void *addr, size_t offset, size_t size);
ssize_t ext_read(fd_t *file, void *addr, size_t offset, size_t size);
int ext_mkfile(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_mkdir(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_delete(vfs_node_t parent, vfs_node_t node);
int ext_rename(vfs_node_t node, const char *new);
int ext_stat(vfs_node_t node);
int ext_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg);
int ext_poll(vfs_node_t node, size_t events);
