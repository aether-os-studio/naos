#pragma once

#include <fs/vfs/vfs.h>

typedef struct tmpfs_fs_info {
    uint64_t next_ino;
    dev64_t dev;
    spinlock_t lock;
} tmpfs_fs_info_t;

typedef struct tmpfs_dirent {
    struct llist_header node;
    char *name;
    struct vfs_inode *inode;
} tmpfs_dirent_t;

typedef struct tmpfs_inode_info {
    struct vfs_inode vfs_inode;
    spinlock_t lock;
    char *data;
    size_t size;
    size_t capacity;
    struct llist_header children;
} tmpfs_inode_info_t;

void tmpfs_init(void);
