#pragma once

#include <fs/vfs/vfs.h>
#include <fs/vfs/paged_store.h>

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
    mutex_t lock;
    paged_file_store_t store;
    char *link_target;
    struct llist_header children;
} tmpfs_inode_info_t;

void tmpfs_init(void);
