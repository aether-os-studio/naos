#include "fs/vfs/vfs_internal.h"
#include "mm/mm.h"

struct vfs_super_block *vfs_alloc_super(struct vfs_file_system_type *type,
                                        unsigned long sb_flags) {
    struct vfs_super_block *sb = calloc(1, sizeof(*sb));
    if (!sb)
        return NULL;

    sb->s_type = type;
    sb->s_flags = sb_flags;
    spin_init(&sb->s_inode_lock);
    spin_init(&sb->s_mount_lock);
    llist_init_head(&sb->s_inodes);
    llist_init_head(&sb->s_mounts);
    vfs_ref_init(&sb->s_ref, 1);
    sb->s_seq = 1;
    return sb;
}

bool vfs_get_super(struct vfs_super_block *sb) {
    if (!sb)
        return false;
    return vfs_ref_try_get(&sb->s_ref);
}

void vfs_put_super(struct vfs_super_block *sb) {
    if (!sb)
        return;
    if (!vfs_ref_put(&sb->s_ref))
        return;
    if (sb->s_op && sb->s_op->put_super)
        sb->s_op->put_super(sb);
    free(sb);
}
