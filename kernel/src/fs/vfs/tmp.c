#include <fs/vfs/tmp.h>
#include <fs/vfs/tmpfs_limit.h>
#include <mm/mm.h>

#define MAX_TMPFS_FILE_SIZE (64 * 1024 * 1024)

spinlock_t tmpfs_mem_limit_lock = SPIN_INIT;
uint64_t tmpfs_mem_used = 0;

static struct vfs_file_system_type tmpfs_fs_type;
static const struct vfs_super_operations tmpfs_super_ops;
static const struct vfs_inode_operations tmpfs_inode_ops;
static const struct vfs_file_operations tmpfs_dir_ops;
static const struct vfs_file_operations tmpfs_file_ops;

static inline tmpfs_fs_info_t *tmpfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (tmpfs_fs_info_t *)sb->s_fs_info : NULL;
}

static inline tmpfs_inode_info_t *tmpfs_i(struct vfs_inode *inode) {
    return inode ? container_of(inode, tmpfs_inode_info_t, vfs_inode) : NULL;
}

static unsigned char tmpfs_dtype(umode_t mode) {
    if (S_ISDIR(mode))
        return DT_DIR;
    if (S_ISLNK(mode))
        return DT_LNK;
    if (S_ISCHR(mode))
        return DT_CHR;
    if (S_ISBLK(mode))
        return DT_BLK;
    if (S_ISFIFO(mode))
        return DT_FIFO;
    if (S_ISSOCK(mode))
        return DT_SOCK;
    return DT_REG;
}

int tmpfs_mem_resize_reserve(uint64_t old_size, uint64_t new_size) {
    uint64_t old_aligned = tmpfs_mem_align(old_size);
    uint64_t new_aligned = tmpfs_mem_align(new_size);

    spin_lock(&tmpfs_mem_limit_lock);

    if (new_aligned > old_aligned) {
        uint64_t delta = new_aligned - old_aligned;
        uint64_t limit = tmpfs_mem_limit();
        if (delta > limit || tmpfs_mem_used > limit - delta) {
            spin_unlock(&tmpfs_mem_limit_lock);
            return -ENOMEM;
        }
        tmpfs_mem_used += delta;
    } else {
        uint64_t delta = old_aligned - new_aligned;
        tmpfs_mem_used =
            (delta >= tmpfs_mem_used) ? 0 : (tmpfs_mem_used - delta);
    }

    spin_unlock(&tmpfs_mem_limit_lock);
    return 0;
}

void tmpfs_mem_release(uint64_t size) {
    uint64_t aligned;

    if (!size)
        return;

    aligned = tmpfs_mem_align(size);
    spin_lock(&tmpfs_mem_limit_lock);
    tmpfs_mem_used =
        (aligned >= tmpfs_mem_used) ? 0 : (tmpfs_mem_used - aligned);
    spin_unlock(&tmpfs_mem_limit_lock);
}

static ino64_t tmpfs_next_ino(struct vfs_super_block *sb) {
    tmpfs_fs_info_t *fs = tmpfs_sb_info(sb);
    ino64_t ino;

    spin_lock(&fs->lock);
    ino = ++fs->next_ino;
    spin_unlock(&fs->lock);
    return ino;
}

static tmpfs_dirent_t *tmpfs_find_dirent(struct vfs_inode *dir,
                                         const char *name) {
    tmpfs_inode_info_t *info = tmpfs_i(dir);
    tmpfs_dirent_t *de, *tmp;

    if (!info || !S_ISDIR(dir->i_mode) || !name)
        return NULL;

    llist_for_each(de, tmp, &info->children, node) {
        if (de->name && streq(de->name, name))
            return de;
    }
    return NULL;
}

static int tmpfs_add_dirent(struct vfs_inode *dir, const char *name,
                            struct vfs_inode *inode) {
    tmpfs_inode_info_t *info = tmpfs_i(dir);
    tmpfs_dirent_t *de;

    if (!info || !inode || !name || !name[0])
        return -EINVAL;
    if (tmpfs_find_dirent(dir, name))
        return -EEXIST;

    de = calloc(1, sizeof(*de));
    if (!de)
        return -ENOMEM;

    de->name = strdup(name);
    if (!de->name) {
        free(de);
        return -ENOMEM;
    }

    de->inode = vfs_igrab(inode);
    llist_init_head(&de->node);
    llist_append(&info->children, &de->node);
    return 0;
}

static tmpfs_dirent_t *tmpfs_detach_dirent(struct vfs_inode *dir,
                                           const char *name) {
    tmpfs_inode_info_t *info = tmpfs_i(dir);
    tmpfs_dirent_t *de, *tmp;

    if (!info || !name)
        return NULL;

    llist_for_each(de, tmp, &info->children, node) {
        if (!de->name || !streq(de->name, name))
            continue;
        llist_delete(&de->node);
        return de;
    }
    return NULL;
}

static void tmpfs_free_dirent(tmpfs_dirent_t *de) {
    if (!de)
        return;
    if (de->inode)
        vfs_iput(de->inode);
    if (de->name)
        free(de->name);
    free(de);
}

static int tmpfs_resize_inode(struct vfs_inode *inode, uint64_t new_size) {
    tmpfs_inode_info_t *info = tmpfs_i(inode);
    uint64_t old_capacity;
    uint64_t new_capacity;
    void *new_data = NULL;
    int ret;

    if (!info || S_ISDIR(inode->i_mode))
        return -EINVAL;
    if (new_size > MAX_TMPFS_FILE_SIZE)
        return -EFBIG;

    old_capacity = info->capacity;
    new_capacity = new_size ? tmpfs_mem_align(new_size) : 0;
    if (old_capacity == new_capacity) {
        if (new_size > info->size && info->data)
            memset(info->data + info->size, 0, new_size - info->size);
        info->size = new_size;
        inode->i_size = new_size;
        inode->i_blocks = tmpfs_mem_align(new_size) >> 9;
        inode->i_version++;
        return 0;
    }

    ret = tmpfs_mem_resize_reserve(old_capacity, new_capacity);
    if (ret < 0)
        return ret;

    if (new_capacity) {
        new_data = alloc_frames_bytes(new_capacity);
        if (!new_data) {
            tmpfs_mem_resize_reserve(new_capacity, old_capacity);
            return -ENOMEM;
        }
        memset(new_data, 0, new_capacity);
        if (info->data && info->size) {
            memcpy(new_data, info->data,
                   MIN((uint64_t)info->size, MIN(old_capacity, new_capacity)));
        }
    }

    if (info->data && old_capacity)
        free_frames_bytes(info->data, old_capacity);

    info->data = new_data;
    info->capacity = new_capacity;
    info->size = new_size;
    inode->i_size = new_size;
    inode->i_blocks = tmpfs_mem_align(new_size) >> 9;
    inode->i_version++;
    return 0;
}

static struct vfs_inode *tmpfs_new_inode(struct vfs_super_block *sb,
                                         umode_t mode) {
    struct vfs_inode *inode = vfs_alloc_inode(sb);
    tmpfs_inode_info_t *info = tmpfs_i(inode);

    if (!inode)
        return NULL;

    spin_init(&info->lock);
    llist_init_head(&info->children);
    inode->i_ino = tmpfs_next_ino(sb);
    inode->i_mode = mode;
    inode->i_uid = 0;
    inode->i_gid = 0;
    inode->inode = inode->i_ino;
    inode->type = S_ISDIR(mode)    ? file_dir
                  : S_ISLNK(mode)  ? file_symlink
                  : S_ISBLK(mode)  ? file_block
                  : S_ISCHR(mode)  ? file_stream
                  : S_ISFIFO(mode) ? file_fifo
                  : S_ISSOCK(mode) ? file_socket
                                   : file_none;
    inode->i_nlink = S_ISDIR(mode) ? 2 : 1;
    inode->i_size = 0;
    inode->i_blocks = 0;
    inode->i_blkbits = 12;
    inode->i_atime.sec = inode->i_btime.sec = inode->i_ctime.sec =
        inode->i_mtime.sec = (int64_t)(nano_time() / 1000000000ULL);
    inode->i_mapping.host = inode;
    return inode;
}

static struct vfs_dentry *tmpfs_lookup(struct vfs_inode *dir,
                                       struct vfs_dentry *dentry,
                                       unsigned int flags) {
    tmpfs_dirent_t *de;

    (void)flags;
    if (!dir || !dentry)
        return ERR_PTR(-EINVAL);

    de = tmpfs_find_dirent(dir, dentry->d_name.name);
    if (de) {
        vfs_d_instantiate(dentry, de->inode);
    } else {
        vfs_d_instantiate(dentry, NULL);
    }
    return dentry;
}

static int tmpfs_create_common(struct vfs_inode *dir, struct vfs_dentry *dentry,
                               umode_t mode, const char *symlink_target,
                               dev64_t rdev) {
    struct vfs_inode *inode;
    tmpfs_inode_info_t *info;
    int ret;

    if (!dir || !dentry || !S_ISDIR(dir->i_mode))
        return -ENOTDIR;
    if (tmpfs_find_dirent(dir, dentry->d_name.name))
        return -EEXIST;

    inode = tmpfs_new_inode(dir->i_sb, mode);
    if (!inode)
        return -ENOMEM;

    info = tmpfs_i(inode);
    inode->i_rdev = rdev;
    inode->i_op = dir->i_op;

    ret = tmpfs_add_dirent(dir, dentry->d_name.name, inode);
    if (ret < 0) {
        vfs_iput(inode);
        return ret;
    }

    if (S_ISDIR(mode)) {
        inode->i_fop = dir->i_fop;
        dir->i_nlink++;
    } else {
        inode->i_fop = &tmpfs_file_ops;
    }

    if (S_ISLNK(mode) && symlink_target) {
        ret = tmpfs_resize_inode(inode, strlen(symlink_target));
        if (ret < 0) {
            tmpfs_free_dirent(tmpfs_detach_dirent(dir, dentry->d_name.name));
            vfs_iput(inode);
            return ret;
        }
        memcpy(info->data, symlink_target, info->size);
    }

    vfs_d_instantiate(dentry, inode);
    vfs_iput(inode);
    return 0;
}

static int tmpfs_create(struct vfs_inode *dir, struct vfs_dentry *dentry,
                        umode_t mode, bool excl) {
    (void)excl;
    return tmpfs_create_common(dir, dentry, (mode & 07777) | S_IFREG, NULL, 0);
}

static int tmpfs_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                       umode_t mode) {
    return tmpfs_create_common(dir, dentry, (mode & 07777) | S_IFDIR, NULL, 0);
}

static int tmpfs_mknod(struct vfs_inode *dir, struct vfs_dentry *dentry,
                       umode_t mode, dev64_t dev) {
    return tmpfs_create_common(dir, dentry, mode, NULL, dev);
}

static int tmpfs_symlink(struct vfs_inode *dir, struct vfs_dentry *dentry,
                         const char *target) {
    return tmpfs_create_common(dir, dentry, S_IFLNK | 0777, target, 0);
}

static int tmpfs_link(struct vfs_dentry *old_dentry, struct vfs_inode *dir,
                      struct vfs_dentry *new_dentry) {
    int ret;

    if (!old_dentry || !old_dentry->d_inode || !dir || !new_dentry)
        return -EINVAL;
    if (S_ISDIR(old_dentry->d_inode->i_mode))
        return -EPERM;
    if (old_dentry->d_inode->i_sb != dir->i_sb)
        return -EXDEV;

    ret = tmpfs_add_dirent(dir, new_dentry->d_name.name, old_dentry->d_inode);
    if (ret < 0)
        return ret;

    old_dentry->d_inode->i_nlink++;
    vfs_d_instantiate(new_dentry, old_dentry->d_inode);
    return 0;
}

static int tmpfs_unlink(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    tmpfs_dirent_t *de;

    if (!dir || !dentry || !dentry->d_inode)
        return -ENOENT;
    if (S_ISDIR(dentry->d_inode->i_mode))
        return -EISDIR;

    de = tmpfs_detach_dirent(dir, dentry->d_name.name);
    if (!de)
        return -ENOENT;

    if (de->inode->i_nlink)
        de->inode->i_nlink--;
    tmpfs_free_dirent(de);
    return 0;
}

static int tmpfs_rmdir(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    tmpfs_dirent_t *de;
    tmpfs_inode_info_t *info;

    if (!dir || !dentry || !dentry->d_inode ||
        !S_ISDIR(dentry->d_inode->i_mode))
        return -ENOTDIR;

    info = tmpfs_i(dentry->d_inode);
    if (!llist_empty(&info->children))
        return -ENOTEMPTY;

    de = tmpfs_detach_dirent(dir, dentry->d_name.name);
    if (!de)
        return -ENOENT;

    if (dir->i_nlink)
        dir->i_nlink--;
    if (de->inode->i_nlink >= 2)
        de->inode->i_nlink -= 2;
    tmpfs_free_dirent(de);
    return 0;
}

static int tmpfs_rename(struct vfs_rename_ctx *ctx) {
    tmpfs_dirent_t *old_de;
    tmpfs_dirent_t *victim = NULL;

    if (!ctx || !ctx->old_dir || !ctx->new_dir || !ctx->old_dentry ||
        !ctx->new_dentry) {
        return -EINVAL;
    }

    if (ctx->flags & (VFS_RENAME_EXCHANGE | VFS_RENAME_WHITEOUT))
        return -EOPNOTSUPP;

    old_de = tmpfs_detach_dirent(ctx->old_dir, ctx->old_dentry->d_name.name);
    if (!old_de)
        return -ENOENT;

    victim = tmpfs_detach_dirent(ctx->new_dir, ctx->new_dentry->d_name.name);
    if (victim) {
        if (S_ISDIR(victim->inode->i_mode) != S_ISDIR(old_de->inode->i_mode)) {
            llist_init_head(&old_de->node);
            llist_append(&tmpfs_i(ctx->old_dir)->children, &old_de->node);
            llist_init_head(&victim->node);
            llist_append(&tmpfs_i(ctx->new_dir)->children, &victim->node);
            return -ENOTEMPTY;
        }
        tmpfs_free_dirent(victim);
    } else if (ctx->flags & VFS_RENAME_NOREPLACE) {
        llist_init_head(&old_de->node);
        llist_append(&tmpfs_i(ctx->old_dir)->children, &old_de->node);
        return -EEXIST;
    }

    free(old_de->name);
    old_de->name = strdup(ctx->new_dentry->d_name.name);
    llist_init_head(&old_de->node);
    llist_append(&tmpfs_i(ctx->new_dir)->children, &old_de->node);
    return 0;
}

static const char *tmpfs_get_link(struct vfs_dentry *dentry,
                                  struct vfs_inode *inode,
                                  struct vfs_nameidata *nd) {
    tmpfs_inode_info_t *info = tmpfs_i(inode);
    (void)dentry;
    (void)nd;
    return info ? info->data : ERR_PTR(-EINVAL);
}

static int tmpfs_permission(struct vfs_inode *inode, int mask) {
    (void)inode;
    (void)mask;
    return 0;
}

static int tmpfs_getattr(const struct vfs_path *path, struct vfs_kstat *stat,
                         uint32_t request_mask, unsigned int flags) {
    (void)request_mask;
    (void)flags;
    vfs_fill_generic_kstat(path, stat);
    return 0;
}

static int tmpfs_setattr(struct vfs_dentry *dentry,
                         const struct vfs_kstat *stat) {
    int ret = 0;

    if (!dentry || !dentry->d_inode || !stat)
        return -EINVAL;

    if (stat->mode)
        dentry->d_inode->i_mode = stat->mode;
    dentry->d_inode->i_uid = stat->uid;
    dentry->d_inode->i_gid = stat->gid;
    if (!S_ISDIR(dentry->d_inode->i_mode) &&
        stat->size != dentry->d_inode->i_size)
        ret = tmpfs_resize_inode(dentry->d_inode, stat->size);
    dentry->d_inode->inode = dentry->d_inode->i_ino;
    dentry->d_inode->type = S_ISDIR(dentry->d_inode->i_mode)    ? file_dir
                            : S_ISLNK(dentry->d_inode->i_mode)  ? file_symlink
                            : S_ISBLK(dentry->d_inode->i_mode)  ? file_block
                            : S_ISCHR(dentry->d_inode->i_mode)  ? file_stream
                            : S_ISFIFO(dentry->d_inode->i_mode) ? file_fifo
                            : S_ISSOCK(dentry->d_inode->i_mode) ? file_socket
                                                                : file_none;
    return ret;
}

static loff_t tmpfs_llseek(struct vfs_file *file, loff_t offset, int whence) {
    loff_t pos;

    if (!file || !file->f_inode)
        return -EBADF;

    mutex_lock(&file->f_pos_lock);
    switch (whence) {
    case SEEK_SET:
        pos = offset;
        break;
    case SEEK_CUR:
        pos = file->f_pos + offset;
        break;
    case SEEK_END:
        pos = (loff_t)file->f_inode->i_size + offset;
        break;
    default:
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    if (pos < 0) {
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    file->f_pos = pos;
    mutex_unlock(&file->f_pos_lock);
    return pos;
}

static ssize_t tmpfs_read(struct vfs_file *file, void *buf, size_t count,
                          loff_t *ppos) {
    tmpfs_inode_info_t *info;
    size_t pos, n;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;
    info = tmpfs_i(file->f_inode);
    pos = (size_t)*ppos;
    if (pos >= info->size)
        return 0;

    n = MIN(count, info->size - pos);
    memcpy(buf, info->data + pos, n);
    *ppos += (loff_t)n;
    return (ssize_t)n;
}

static ssize_t tmpfs_write(struct vfs_file *file, const void *buf, size_t count,
                           loff_t *ppos) {
    tmpfs_inode_info_t *info;
    uint64_t end;
    int ret;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;

    info = tmpfs_i(file->f_inode);
    if (*ppos < 0)
        return -EINVAL;
    if ((uint64_t)*ppos > UINT64_MAX - count)
        return -EFBIG;

    end = (uint64_t)*ppos + count;
    ret = tmpfs_resize_inode(file->f_inode, MAX((uint64_t)info->size, end));
    if (ret < 0)
        return ret;

    memcpy(info->data + *ppos, buf, count);
    if (end > info->size)
        info->size = end;
    file->f_inode->i_size = info->size;
    file->f_inode->i_version++;
    *ppos += (loff_t)count;
    return (ssize_t)count;
}

static int tmpfs_iterate_shared(struct vfs_file *file,
                                struct vfs_dir_context *ctx) {
    tmpfs_inode_info_t *info;
    tmpfs_dirent_t *de, *tmp;
    loff_t index = 0;

    if (!file || !file->f_inode || !ctx || !S_ISDIR(file->f_inode->i_mode))
        return -ENOTDIR;

    info = tmpfs_i(file->f_inode);
    llist_for_each(de, tmp, &info->children, node) {
        if (index++ < ctx->pos)
            continue;
        if (ctx->actor(ctx, de->name, (int)strlen(de->name), index,
                       de->inode->i_ino, tmpfs_dtype(de->inode->i_mode))) {
            break;
        }
        ctx->pos = index;
    }

    file->f_pos = ctx->pos;
    return 0;
}

static int tmpfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    if (!inode || !file)
        return -EINVAL;
    file->f_op = inode->i_fop;
    return 0;
}

static int tmpfs_release(struct vfs_inode *inode, struct vfs_file *file) {
    (void)inode;
    (void)file;
    return 0;
}

static int tmpfs_fsync(struct vfs_file *file, loff_t start, loff_t end,
                       int datasync) {
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    return 0;
}

static __poll_t tmpfs_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    (void)file;
    (void)pt;
    return EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM;
}

static struct vfs_inode *tmpfs_alloc_inode(struct vfs_super_block *sb) {
    tmpfs_inode_info_t *info = calloc(1, sizeof(*info));
    if (!info)
        return NULL;
    return &info->vfs_inode;
}

static void tmpfs_destroy_inode(struct vfs_inode *inode) {
    tmpfs_inode_info_t *info = tmpfs_i(inode);
    free(info);
}

static void tmpfs_evict_inode(struct vfs_inode *inode) {
    tmpfs_inode_info_t *info = tmpfs_i(inode);
    tmpfs_dirent_t *de, *tmp;

    if (!info)
        return;

    if (info->data && info->capacity) {
        tmpfs_mem_release(info->capacity);
        free_frames_bytes(info->data, info->capacity);
        info->data = NULL;
        info->capacity = 0;
        info->size = 0;
    }

    llist_for_each(de, tmp, &info->children, node) {
        llist_delete(&de->node);
        tmpfs_free_dirent(de);
    }
}

static void tmpfs_put_super(struct vfs_super_block *sb) {
    if (sb && sb->s_fs_info)
        free(sb->s_fs_info);
}

static int tmpfs_statfs(struct vfs_path *path, void *buf) {
    (void)path;
    (void)buf;
    return 0;
}

static int tmpfs_init_fs_context(struct vfs_fs_context *fc) {
    fc->sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!fc->sb)
        return -ENOMEM;
    return 0;
}

static int tmpfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb = fc->sb;
    tmpfs_fs_info_t *fsi;
    struct vfs_inode *root_inode;
    struct vfs_dentry *root_dentry;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};

    if (!sb)
        return -EINVAL;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi)
        return -ENOMEM;
    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    fsi->dev = 0;

    sb->s_fs_info = fsi;
    sb->s_op = &tmpfs_super_ops;
    sb->s_type = &tmpfs_fs_type;
    sb->s_magic = 0x01021994;

    root_inode = tmpfs_new_inode(sb, S_IFDIR | 0755);
    if (!root_inode)
        return -ENOMEM;

    root_inode->i_op = &tmpfs_inode_ops;
    root_inode->i_fop = &tmpfs_dir_ops;

    root_dentry = vfs_d_alloc(sb, NULL, &root_name);
    if (!root_dentry) {
        vfs_iput(root_inode);
        return -ENOMEM;
    }

    vfs_d_instantiate(root_dentry, root_inode);
    sb->s_root = root_dentry;
    vfs_iput(root_inode);
    return 0;
}

static const struct vfs_super_operations tmpfs_super_ops = {
    .alloc_inode = tmpfs_alloc_inode,
    .destroy_inode = tmpfs_destroy_inode,
    .evict_inode = tmpfs_evict_inode,
    .put_super = tmpfs_put_super,
    .statfs = tmpfs_statfs,
};

static const struct vfs_file_operations tmpfs_dir_ops = {
    .llseek = tmpfs_llseek,
    .iterate_shared = tmpfs_iterate_shared,
    .open = tmpfs_open,
    .release = tmpfs_release,
    .fsync = tmpfs_fsync,
    .poll = tmpfs_poll,
};

static const struct vfs_file_operations tmpfs_file_ops = {
    .llseek = tmpfs_llseek,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .open = tmpfs_open,
    .release = tmpfs_release,
    .fsync = tmpfs_fsync,
    .poll = tmpfs_poll,
};

static const struct vfs_inode_operations tmpfs_inode_ops = {
    .lookup = tmpfs_lookup,
    .create = tmpfs_create,
    .link = tmpfs_link,
    .unlink = tmpfs_unlink,
    .symlink = tmpfs_symlink,
    .mkdir = tmpfs_mkdir,
    .rmdir = tmpfs_rmdir,
    .mknod = tmpfs_mknod,
    .rename = tmpfs_rename,
    .get_link = tmpfs_get_link,
    .permission = tmpfs_permission,
    .getattr = tmpfs_getattr,
    .setattr = tmpfs_setattr,
};

static struct vfs_file_system_type tmpfs_fs_type = {
    .name = "tmpfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = tmpfs_init_fs_context,
    .get_tree = tmpfs_get_tree,
};

void tmpfs_init(void) { vfs_register_filesystem(&tmpfs_fs_type); }
