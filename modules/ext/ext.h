#pragma once

#include <fs/vfs/vfs.h>
#include <ext_disk.h>

struct ext_mount_ctx;

typedef struct ext_handle {
    vfs_node_t node;
    uint32_t ino;
    bool device_opened;
    bool inode_valid;
    bool inode_dirty;
    ext_inode_disk_t inode_cache;
} ext_handle_t;

int ext_mount(uint64_t dev, vfs_node_t node);
void ext_unmount(vfs_node_t node);
int ext_remount(vfs_node_t old, vfs_node_t node);
void ext_open(vfs_node_t parent, const char *name, vfs_node_t node);
bool ext_close(vfs_node_t node);
ssize_t ext_write(fd_t *file, const void *addr, size_t offset, size_t size);
ssize_t ext_read(fd_t *file, void *addr, size_t offset, size_t size);
ssize_t ext_readlink(vfs_node_t node, void *addr, size_t offset, size_t size);
int ext_mkfile(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_link(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_symlink(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
              uint16_t mode, int dev);
int ext_mkdir(vfs_node_t parent, const char *name, vfs_node_t node);
int ext_chmod(vfs_node_t node, uint16_t mode);
int ext_chown(vfs_node_t node, uint64_t uid, uint64_t gid);
int ext_delete(vfs_node_t parent, vfs_node_t node);
int ext_rename(vfs_node_t node, const char *new);
int ext_stat(vfs_node_t node);
int ext_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg);
int ext_poll(vfs_node_t node, size_t events);
void ext_resize(vfs_node_t node, uint64_t size);
void *ext_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
              size_t flags);
void ext_free_handle(vfs_node_t node);

extern void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                         uint64_t flags, uint64_t offset);
