#include "fs/vfs/vfs_internal.h"
#include "mm/mm.h"

bool vfs_path_get(struct vfs_path *path) {
    struct vfs_mount *mnt = NULL;
    struct vfs_dentry *dentry = NULL;

    if (!path)
        return false;
    if (path->mnt)
        mnt = vfs_mntget(path->mnt);
    if (path->dentry)
        dentry = vfs_dget(path->dentry);
    if ((path->mnt && !mnt) || (path->dentry && !dentry)) {
        if (dentry)
            vfs_dput(dentry);
        if (mnt)
            vfs_mntput(mnt);
        return false;
    }
    return true;
}

void vfs_path_init(struct vfs_path *path) {
    if (!path)
        return;
    path->mnt = NULL;
    path->dentry = NULL;
}

bool vfs_path_set(struct vfs_path *path, struct vfs_mount *mnt,
                  struct vfs_dentry *dentry) {
    struct vfs_path tmp;

    if (!path)
        return false;
    tmp.mnt = mnt;
    tmp.dentry = dentry;
    if (!vfs_path_get(&tmp))
        return false;
    *path = tmp;
    return true;
}

bool vfs_path_copy(struct vfs_path *dst, const struct vfs_path *src) {
    if (!dst || !src)
        return false;
    return vfs_path_set(dst, src->mnt, src->dentry);
}

bool vfs_path_update(struct vfs_path *dst, const struct vfs_path *src) {
    struct vfs_path tmp = {0};

    if (!dst || !src)
        return false;
    if (!vfs_path_copy(&tmp, src))
        return false;
    vfs_path_put(dst);
    *dst = tmp;
    return true;
}

void vfs_path_move(struct vfs_path *dst, struct vfs_path *src) {
    if (!dst || !src || dst == src)
        return;
    vfs_path_put(dst);
    *dst = *src;
    vfs_path_init(src);
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
    struct vfs_path cursor = {0};
    struct vfs_path limit = {0};
    char *buf;
    char *out;
    size_t pos;

    if (!path || !path->mnt || !path->dentry)
        return strdup("/");

    if (!vfs_path_copy(&cursor, path))
        return strdup("/");
    if (root && root->mnt && root->dentry) {
        if (!vfs_path_copy(&limit, root)) {
            vfs_path_put(&cursor);
            return strdup("/");
        }
    } else if (vfs_root_path.mnt && vfs_root_path.dentry) {
        if (!vfs_path_copy(&limit, &vfs_root_path)) {
            vfs_path_put(&cursor);
            return strdup("/");
        }
    }

    buf = calloc(1, VFS_PATH_MAX);
    if (!buf) {
        vfs_path_put(&cursor);
        vfs_path_put(&limit);
        return NULL;
    }

    pos = VFS_PATH_MAX - 1;
    buf[pos] = '\0';

    while (cursor.mnt && cursor.dentry && !vfs_path_equal(&cursor, &limit)) {
        const char *name;
        size_t len;

        if (cursor.dentry == cursor.mnt->mnt_root && cursor.mnt != limit.mnt &&
            cursor.mnt->mnt_parent && cursor.mnt->mnt_parent != cursor.mnt &&
            cursor.mnt->mnt_mountpoint) {
            struct vfs_mount *next_mnt = vfs_mntget(cursor.mnt->mnt_parent);
            struct vfs_dentry *next_dentry =
                vfs_dget(cursor.mnt->mnt_mountpoint);

            if (!next_mnt || !next_dentry) {
                if (next_dentry)
                    vfs_dput(next_dentry);
                if (next_mnt)
                    vfs_mntput(next_mnt);
                break;
            }
            vfs_path_put(&cursor);
            cursor.mnt = next_mnt;
            cursor.dentry = next_dentry;
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
                vfs_path_put(&cursor);
                vfs_path_put(&limit);
                return NULL;
            }
            pos -= len;
            memcpy(buf + pos, name, len);
        }

        if (pos == 0) {
            free(buf);
            vfs_path_put(&cursor);
            vfs_path_put(&limit);
            return NULL;
        }
        buf[--pos] = '/';
        {
            struct vfs_dentry *parent = vfs_dget(cursor.dentry->d_parent);

            if (!parent)
                break;
            vfs_dput(cursor.dentry);
            cursor.dentry = parent;
        }
    }

    if (pos == VFS_PATH_MAX - 1)
        buf[--pos] = '/';

    out = strdup(buf + pos);
    free(buf);
    vfs_path_put(&cursor);
    vfs_path_put(&limit);
    return out;
}

bool vfs_path_is_ancestor(const struct vfs_path *ancestor,
                          const struct vfs_path *path) {
    struct vfs_path cursor = {0};
    struct vfs_path stable_ancestor = {0};
    bool found = false;

    if (!ancestor || !ancestor->mnt || !ancestor->dentry || !path ||
        !path->mnt || !path->dentry) {
        return false;
    }

    if (!vfs_path_copy(&stable_ancestor, ancestor))
        return false;
    if (!vfs_path_copy(&cursor, path)) {
        vfs_path_put(&stable_ancestor);
        return false;
    }

    while (cursor.mnt && cursor.dentry) {
        if (vfs_path_equal(&stable_ancestor, &cursor)) {
            found = true;
            break;
        }

        if (cursor.dentry == cursor.mnt->mnt_root && cursor.mnt->mnt_parent &&
            cursor.mnt->mnt_parent != cursor.mnt &&
            cursor.mnt->mnt_mountpoint) {
            struct vfs_mount *next_mnt = vfs_mntget(cursor.mnt->mnt_parent);
            struct vfs_dentry *next_dentry =
                vfs_dget(cursor.mnt->mnt_mountpoint);

            if (!next_mnt || !next_dentry) {
                if (next_dentry)
                    vfs_dput(next_dentry);
                if (next_mnt)
                    vfs_mntput(next_mnt);
                break;
            }
            vfs_path_put(&cursor);
            cursor.mnt = next_mnt;
            cursor.dentry = next_dentry;
            continue;
        }

        if (!cursor.dentry->d_parent ||
            cursor.dentry == cursor.dentry->d_parent) {
            break;
        }

        {
            struct vfs_dentry *parent = vfs_dget(cursor.dentry->d_parent);

            if (!parent)
                break;
            vfs_dput(cursor.dentry);
            cursor.dentry = parent;
        }
    }

    vfs_path_put(&cursor);
    vfs_path_put(&stable_ancestor);
    return found;
}
