#pragma once

#include "fs/vfs/vfs.h"

void vfs_dcache_init(void);
void vfs_mount_subsys_init(void);
void vfs_ops_init(void);

void vfs_sync_inode_compat(struct vfs_inode *inode);
void vfs_dentry_unhash(struct vfs_dentry *dentry);

struct vfs_mount *vfs_active_namespace_root_mount(void);
struct vfs_mount *vfs_child_mount_at(struct vfs_mount *parent,
                                     struct vfs_dentry *mountpoint);
struct vfs_mount *
vfs_find_mount_child_by_source(struct vfs_mount *parent,
                               const struct vfs_mount *src_child);
struct vfs_mount *vfs_create_bind_mount(const struct vfs_path *from,
                                        bool recursive);

struct vfs_dentry *vfs_lookup_component(struct vfs_path *parent,
                                        const char *component,
                                        unsigned int flags);
void vfs_follow_mount(struct vfs_path *path);
