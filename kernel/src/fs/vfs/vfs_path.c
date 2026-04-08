#include "fs/vfs/vfs_internal.h"
#include "mm/mm.h"

void vfs_path_get(struct vfs_path *path) {
    if (!path)
        return;
    if (path->mnt)
        vfs_mntget(path->mnt);
    if (path->dentry)
        vfs_dget(path->dentry);
}

void vfs_path_put(struct vfs_path *path) {
    if (!path)
        return;
    if (path->dentry)
        vfs_dput(path->dentry);
    if (path->mnt)
        vfs_mntput(path->mnt);
    path->dentry = NULL;
    path->mnt = NULL;
}

bool vfs_path_equal(const struct vfs_path *a, const struct vfs_path *b) {
    if (!a || !b)
        return false;
    return a->mnt == b->mnt && a->dentry == b->dentry;
}

void vfs_fill_generic_kstat(const struct vfs_path *path,
                            struct vfs_kstat *stat) {
    struct vfs_inode *inode;

    if (!path || !path->dentry || !path->dentry->d_inode || !stat)
        return;
    inode = path->dentry->d_inode;
    memset(stat, 0, sizeof(*stat));
    stat->ino = inode->i_ino;
    stat->dev = inode->i_sb ? inode->i_sb->s_dev : 0;
    stat->rdev = inode->i_rdev;
    stat->mode = inode->i_mode;
    stat->uid = inode->i_uid;
    stat->gid = inode->i_gid;
    stat->nlink = inode->i_nlink;
    stat->size = inode->i_size;
    stat->blocks = inode->i_blocks;
    stat->blksize = 1U << inode->i_blkbits;
    stat->atime = inode->i_atime;
    stat->btime = inode->i_btime;
    stat->ctime = inode->i_ctime;
    stat->mtime = inode->i_mtime;
    stat->mnt_id = path->mnt ? path->mnt->mnt_id : 0;
}

char *vfs_path_to_string(const struct vfs_path *path,
                         const struct vfs_path *root) {
    struct vfs_path cursor;
    const struct vfs_path *limit;
    char *buf;
    char *out;
    size_t pos;

    if (!path || !path->mnt || !path->dentry)
        return strdup("/");

    limit = (root && root->mnt && root->dentry) ? root : &vfs_root_path;
    buf = calloc(1, VFS_PATH_MAX);
    if (!buf)
        return NULL;

    pos = VFS_PATH_MAX - 1;
    buf[pos] = '\0';
    cursor = *path;

    while (cursor.mnt && cursor.dentry && !vfs_path_equal(&cursor, limit)) {
        const char *name;
        size_t len;

        if (cursor.dentry == cursor.mnt->mnt_root && cursor.mnt != limit->mnt &&
            cursor.mnt->mnt_parent && cursor.mnt->mnt_mountpoint) {
            cursor.dentry = cursor.mnt->mnt_mountpoint;
            cursor.mnt = cursor.mnt->mnt_parent;
            continue;
        }

        if (!cursor.dentry->d_parent ||
            cursor.dentry == cursor.dentry->d_parent) {
            break;
        }

        name = cursor.dentry->d_name.name ? cursor.dentry->d_name.name : "";
        len = strlen(name);
        if (len) {
            if (pos < len + 1) {
                free(buf);
                return NULL;
            }
            pos -= len;
            memcpy(buf + pos, name, len);
        }

        if (pos == 0) {
            free(buf);
            return NULL;
        }
        buf[--pos] = '/';
        cursor.dentry = cursor.dentry->d_parent;
    }

    if (pos == VFS_PATH_MAX - 1)
        buf[--pos] = '/';

    out = strdup(buf + pos);
    free(buf);
    return out;
}

bool vfs_path_is_ancestor(const struct vfs_path *ancestor,
                          const struct vfs_path *path) {
    struct vfs_path cursor;

    if (!ancestor || !ancestor->mnt || !ancestor->dentry || !path ||
        !path->mnt || !path->dentry) {
        return false;
    }

    cursor = *path;
    while (cursor.mnt && cursor.dentry) {
        if (vfs_path_equal(ancestor, &cursor))
            return true;

        if (cursor.dentry == cursor.mnt->mnt_root && cursor.mnt->mnt_parent &&
            cursor.mnt->mnt_mountpoint) {
            cursor.dentry = cursor.mnt->mnt_mountpoint;
            cursor.mnt = cursor.mnt->mnt_parent;
            continue;
        }

        if (!cursor.dentry->d_parent ||
            cursor.dentry == cursor.dentry->d_parent) {
            break;
        }

        cursor.dentry = cursor.dentry->d_parent;
    }

    return false;
}
