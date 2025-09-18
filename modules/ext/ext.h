#pragma once

#include <fs/vfs/vfs.h>
#include <lwext4/blockdev/vfs_dev.h>
#include <lwext4/include/ext4_types.h>
#include <lwext4/include/ext4.h>

typedef struct ext_handle {
    vfs_node_t node;
    union {
        ext4_file *file;
        ext4_dir *dir;
    };
} ext_handle_t;

int ext_mount(vfs_node_t dev, vfs_node_t node);
void ext_unmount(void *root);
void ext_open(void *parent, const char *name, vfs_node_t node);
bool ext_close(void *current);
ssize_t ext_write(fd_t *file, const void *addr, size_t offset, size_t size);
ssize_t ext_read(fd_t *file, void *addr, size_t offset, size_t size);
int ext_mkfile(void *parent, const char *name, vfs_node_t node);
int ext_mkdir(void *parent, const char *name, vfs_node_t node);
int ext_delete(void *parent, vfs_node_t node);
int ext_rename(void *current, const char *new);
int ext_stat(void *file, vfs_node_t node);
int ext_ioctl(void *file, ssize_t cmd, ssize_t arg);
int ext_poll(void *file, size_t events);
