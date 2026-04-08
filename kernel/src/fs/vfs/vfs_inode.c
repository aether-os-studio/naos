#include "fs/vfs/vfs_internal.h"
#include "mm/mm.h"

static uint32_t vfs_mode_to_type(umode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        return file_dir;
    case S_IFLNK:
        return file_symlink;
    case S_IFBLK:
        return file_block;
    case S_IFCHR:
        return file_stream;
    case S_IFIFO:
        return file_fifo;
    case S_IFSOCK:
        return file_socket;
    case S_IFREG:
    default:
        return file_none;
    }
}

void vfs_sync_inode_compat(struct vfs_inode *inode) {
    if (!inode)
        return;

    inode->inode = inode->i_ino;
    inode->type = vfs_mode_to_type(inode->i_mode);
}

struct vfs_inode *vfs_alloc_inode(struct vfs_super_block *sb) {
    struct vfs_inode *inode = NULL;

    if (!sb)
        return NULL;
    if (sb->s_op && sb->s_op->alloc_inode)
        inode = sb->s_op->alloc_inode(sb);
    if (!inode)
        inode = malloc(sizeof(*inode));
    if (!inode)
        return NULL;

    memset(inode, 0, sizeof(*inode));
    inode->i_sb = sb;
    inode->i_blkbits = 12;
    inode->i_state = VFS_I_NEW;
    inode->i_mapping.host = inode;
    inode->inode = 0;
    inode->type = file_none;
    inode->rw_hint = 0;
    spin_init(&inode->i_lock);
    mutex_init(&inode->i_rwsem);
    spin_init(&inode->flock_lock.spin);
    inode->flock_lock.l_type = F_UNLCK;
    inode->flock_lock.owner = 0;
    spin_init(&inode->file_locks_lock);
    llist_init_head(&inode->file_locks);
    llist_init_head(&inode->i_dentry_aliases);
    llist_init_head(&inode->i_sb_list);
    spin_init(&inode->poll_waiters_lock);
    llist_init_head(&inode->poll_waiters);
    vfs_ref_init(&inode->i_ref, 1);

    spin_lock(&sb->s_inode_lock);
    llist_append(&sb->s_inodes, &inode->i_sb_list);
    spin_unlock(&sb->s_inode_lock);

    return inode;
}

struct vfs_inode *vfs_igrab(struct vfs_inode *inode) {
    if (!inode)
        return NULL;
    vfs_ref_get(&inode->i_ref);
    return inode;
}

void vfs_iput(struct vfs_inode *inode) {
    if (!inode)
        return;
    if (!vfs_ref_put(&inode->i_ref))
        return;

    if (inode->i_sb && !llist_empty(&inode->i_sb_list)) {
        spin_lock(&inode->i_sb->s_inode_lock);
        if (!llist_empty(&inode->i_sb_list))
            llist_delete(&inode->i_sb_list);
        spin_unlock(&inode->i_sb->s_inode_lock);
    }
    if (inode->i_sb && inode->i_sb->s_op && inode->i_sb->s_op->evict_inode)
        inode->i_sb->s_op->evict_inode(inode);
    if (inode->i_sb && inode->i_sb->s_op && inode->i_sb->s_op->destroy_inode)
        inode->i_sb->s_op->destroy_inode(inode);
    else
        free(inode);
}

void vfs_inode_init_owner(struct vfs_inode *inode, struct vfs_inode *dir,
                          umode_t mode) {
    if (!inode)
        return;
    inode->i_mode = mode;
    inode->i_uid = dir ? dir->i_uid : 0;
    inode->i_gid = dir ? dir->i_gid : 0;
    inode->type = vfs_mode_to_type(mode);
}
