#include <libs/keys.h>
#include <fs/vfs/vfs.h>
#include <fs/sys.h>
#include <block/partition.h>
#include <dev/device.h>
#include <drivers/logger.h>
#include <drivers/tty.h>
#include <dev/pty.h>
#include <net/netlink.h>
#include <boot/boot.h>
#include <arch/arch.h>
#include <fs/vfs/paged_store.h>
#include <fs/vfs/tmpfs_limit.h>
#include <mm/mm_syscall.h>

#define DEVTMPFS_MAGIC 0x01021994ULL
#define MAX_DEVTMPFS_FILE_SIZE (128 * 1024 * 1024)

typedef struct devtmpfs_dirent {
    struct llist_header node;
    char *name;
    struct vfs_inode *inode;
} devtmpfs_dirent_t;

typedef struct devtmpfs_inode_info {
    struct vfs_inode vfs_inode;
    mutex_t lock;
    struct llist_header children;
    paged_file_store_t store;
    char *link_target;
} devtmpfs_inode_info_t;

typedef struct devtmpfs_fs_info {
    mutex_t populate_lock;
    bool populated;
    bool populating;
} devtmpfs_fs_info_t;

static struct vfs_file_system_type devtmpfs_fs_type;
static const struct vfs_super_operations devtmpfs_super_ops;
static const struct vfs_inode_operations devtmpfs_inode_ops;
static const struct vfs_file_operations devtmpfs_dir_file_ops;
static const struct vfs_file_operations devtmpfs_file_ops;
static void devtmpfs_free_dirent(devtmpfs_dirent_t *de);

vfs_node_t *devtmpfs_root = NULL;
bool devfs_initialized = false;

static inline devtmpfs_inode_info_t *devtmpfs_i(vfs_node_t *inode) {
    return inode ? container_of(inode, devtmpfs_inode_info_t, vfs_inode) : NULL;
}

static devtmpfs_dirent_t *
devtmpfs_find_dirent_locked(devtmpfs_inode_info_t *info, const char *name) {
    devtmpfs_dirent_t *de, *tmp;

    if (!info || !name)
        return NULL;

    llist_for_each(de, tmp, &info->children, node) {
        if (de->name && streq(de->name, name))
            return de;
    }

    return NULL;
}

static void devtmpfs_lock_dir_infos(devtmpfs_inode_info_t *a,
                                    devtmpfs_inode_info_t *b) {
    if (!a)
        return;

    if (!b || a == b) {
        mutex_lock(&a->lock);
        return;
    }

    if ((uintptr_t)a < (uintptr_t)b) {
        mutex_lock(&a->lock);
        mutex_lock(&b->lock);
    } else {
        mutex_lock(&b->lock);
        mutex_lock(&a->lock);
    }
}

static void devtmpfs_unlock_dir_infos(devtmpfs_inode_info_t *a,
                                      devtmpfs_inode_info_t *b) {
    if (!a)
        return;

    if (!b || a == b) {
        mutex_unlock(&a->lock);
        return;
    }

    mutex_unlock(&a->lock);
    mutex_unlock(&b->lock);
}

static inline devtmpfs_fs_info_t *devtmpfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (devtmpfs_fs_info_t *)sb->s_fs_info : NULL;
}

static void devtmpfs_ensure_populated(struct vfs_super_block *sb);
static void setup_console_symlinks(void);

static unsigned char devtmpfs_dtype(umode_t mode) {
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

static int devtmpfs_resize_inode(struct vfs_inode *inode, uint64_t new_size) {
    devtmpfs_inode_info_t *info = devtmpfs_i(inode);
    uint64_t old_size;
    size_t old_pages;
    size_t new_pages;
    int ret;

    if (!info || S_ISDIR(inode->i_mode) || S_ISCHR(inode->i_mode) ||
        S_ISBLK(inode->i_mode))
        return -EINVAL;
    if (new_size > MAX_DEVTMPFS_FILE_SIZE)
        return -EFBIG;

    old_size = info->store.size;
    if (old_size == new_size)
        return 0;

    old_pages = paged_file_store_pages_for_size(old_size);
    new_pages = paged_file_store_pages_for_size(new_size);

    ret = tmpfs_mem_resize_reserve(old_size, new_size);
    if (ret < 0)
        return ret;

    mutex_lock(&info->lock);
    if (new_size > old_size) {
        ret = paged_file_store_ensure_slots(&info->store, new_pages);
        if (ret < 0) {
            mutex_unlock(&info->lock);
            tmpfs_mem_resize_reserve(new_size, old_size);
            return ret;
        }
    } else {
        paged_file_store_zero_tail(&info->store, new_size);
    }

    info->store.size = new_size;
    inode->i_size = new_size;
    inode->i_blocks = tmpfs_mem_align(new_size) >> 9;
    inode->i_version++;
    mutex_unlock(&info->lock);

    if (new_size < old_size) {
        uint64_t zap_start = PADDING_UP(new_size, PAGE_SIZE);
        uint64_t zap_end = PADDING_UP(old_size, PAGE_SIZE);

        if (zap_start < zap_end)
            paged_file_store_zap_shared_mappings(inode, zap_start, zap_end);

        for (size_t i = new_pages; i < old_pages; i++) {
            uint64_t paddr = 0;

            mutex_lock(&info->lock);
            if (i < info->store.page_slots) {
                paddr = info->store.pages[i];
                info->store.pages[i] = 0;
            }
            mutex_unlock(&info->lock);

            if (paddr)
                address_release(paddr);
        }
    }

    return 0;
}

static devtmpfs_dirent_t *devtmpfs_find_dirent(struct vfs_inode *dir,
                                               const char *name) {
    devtmpfs_inode_info_t *info = devtmpfs_i(dir);
    devtmpfs_dirent_t *de;

    if (!info || !S_ISDIR(dir->i_mode) || !name)
        return NULL;

    mutex_lock(&info->lock);
    de = devtmpfs_find_dirent_locked(info, name);
    mutex_unlock(&info->lock);
    return de;
}

static int devtmpfs_add_dirent(struct vfs_inode *dir, const char *name,
                               struct vfs_inode *inode) {
    devtmpfs_inode_info_t *info = devtmpfs_i(dir);
    devtmpfs_dirent_t *de;

    if (!info || !inode || !name || !name[0])
        return -EINVAL;

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
    mutex_lock(&info->lock);
    if (devtmpfs_find_dirent_locked(info, name)) {
        mutex_unlock(&info->lock);
        devtmpfs_free_dirent(de);
        return -EEXIST;
    }
    llist_append(&info->children, &de->node);
    mutex_unlock(&info->lock);
    return 0;
}

static devtmpfs_dirent_t *devtmpfs_detach_dirent(struct vfs_inode *dir,
                                                 const char *name) {
    devtmpfs_inode_info_t *info = devtmpfs_i(dir);
    devtmpfs_dirent_t *de, *tmp;

    if (!info || !name)
        return NULL;

    mutex_lock(&info->lock);
    llist_for_each(de, tmp, &info->children, node) {
        if (!de->name || !streq(de->name, name))
            continue;
        llist_delete(&de->node);
        mutex_unlock(&info->lock);
        return de;
    }
    mutex_unlock(&info->lock);
    return NULL;
}

static void devtmpfs_free_dirent(devtmpfs_dirent_t *de) {
    if (!de)
        return;
    if (de->inode)
        vfs_iput(de->inode);
    free(de->name);
    free(de);
}

static struct vfs_inode *devtmpfs_new_inode(struct vfs_super_block *sb,
                                            umode_t mode) {
    struct vfs_inode *inode = vfs_alloc_inode(sb);
    devtmpfs_inode_info_t *info = devtmpfs_i(inode);

    if (!inode)
        return NULL;

    mutex_init(&info->lock);
    llist_init_head(&info->children);
    inode->i_op = &devtmpfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &devtmpfs_dir_file_ops : &devtmpfs_file_ops;
    inode->i_mode = mode;
    inode->i_uid = 0;
    inode->i_gid = 0;
    inode->i_nlink = S_ISDIR(mode) ? 2 : 1;
    inode->i_blkbits = 12;
    inode->i_ino = (ino64_t)(uintptr_t)inode;
    inode->inode = inode->i_ino;
    inode->type = S_ISDIR(mode)    ? file_dir
                  : S_ISLNK(mode)  ? file_symlink
                  : S_ISBLK(mode)  ? file_block
                  : S_ISCHR(mode)  ? file_stream
                  : S_ISFIFO(mode) ? file_fifo
                  : S_ISSOCK(mode) ? file_socket
                                   : file_none;
    inode->i_atime.sec = inode->i_btime.sec = inode->i_ctime.sec =
        inode->i_mtime.sec = (int64_t)(nano_time() / 1000000000ULL);
    return inode;
}

static struct vfs_dentry *devtmpfs_lookup(struct vfs_inode *dir,
                                          struct vfs_dentry *dentry,
                                          unsigned int flags) {
    devtmpfs_inode_info_t *info;
    struct vfs_inode *inode = NULL;

    (void)flags;
    if (!dir || !dentry)
        return ERR_PTR(-EINVAL);

    devtmpfs_ensure_populated(dir->i_sb);

    info = devtmpfs_i(dir);
    if (!info)
        return ERR_PTR(-EINVAL);

    mutex_lock(&info->lock);
    devtmpfs_dirent_t *de =
        devtmpfs_find_dirent_locked(info, dentry->d_name.name);
    if (de)
        inode = vfs_igrab(de->inode);
    mutex_unlock(&info->lock);

    vfs_d_instantiate(dentry, inode);
    if (inode)
        vfs_iput(inode);
    return dentry;
}

static int devtmpfs_create_common(struct vfs_inode *dir,
                                  struct vfs_dentry *dentry, umode_t mode,
                                  const char *symlink_target, dev64_t rdev) {
    struct vfs_inode *inode;
    devtmpfs_inode_info_t *info;
    int ret;

    if (!dir || !dentry || !S_ISDIR(dir->i_mode))
        return -ENOTDIR;
    if (devtmpfs_find_dirent(dir, dentry->d_name.name))
        return -EEXIST;

    inode = devtmpfs_new_inode(dir->i_sb, mode);
    if (!inode)
        return -ENOMEM;

    info = devtmpfs_i(inode);
    inode->i_rdev = rdev;

    if (S_ISLNK(mode) && symlink_target) {
        info->link_target = strdup(symlink_target);
        if (!info->link_target) {
            vfs_iput(inode);
            return -ENOMEM;
        }
        ret = devtmpfs_resize_inode(inode, strlen(symlink_target));
        if (ret < 0) {
            free(info->link_target);
            info->link_target = NULL;
            vfs_iput(inode);
            return ret;
        }

        loff_t pos = 0;
        mutex_lock(&info->lock);
        ret = (int)paged_file_store_write_locked(&info->store, symlink_target,
                                                 strlen(symlink_target), &pos);
        mutex_unlock(&info->lock);
        if (ret < 0) {
            free(info->link_target);
            info->link_target = NULL;
            vfs_iput(inode);
            return ret;
        }
    }

    ret = devtmpfs_add_dirent(dir, dentry->d_name.name, inode);
    if (ret < 0) {
        vfs_iput(inode);
        return ret;
    }

    if (S_ISDIR(mode))
        dir->i_nlink++;

    vfs_d_instantiate(dentry, inode);
    vfs_iput(inode);
    return 0;
}

static int devtmpfs_create(struct vfs_inode *dir, struct vfs_dentry *dentry,
                           umode_t mode, bool excl) {
    (void)excl;
    return devtmpfs_create_common(dir, dentry, (mode & 07777) | S_IFREG, NULL,
                                  0);
}

static int devtmpfs_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                          umode_t mode) {
    return devtmpfs_create_common(dir, dentry, (mode & 07777) | S_IFDIR, NULL,
                                  0);
}

static int devtmpfs_mknod(struct vfs_inode *dir, struct vfs_dentry *dentry,
                          umode_t mode, dev64_t dev) {
    return devtmpfs_create_common(dir, dentry, mode, NULL, dev);
}

static int devtmpfs_symlink(struct vfs_inode *dir, struct vfs_dentry *dentry,
                            const char *target) {
    return devtmpfs_create_common(dir, dentry, S_IFLNK | 0777, target, 0);
}

static int devtmpfs_link(struct vfs_dentry *old_dentry, struct vfs_inode *dir,
                         struct vfs_dentry *new_dentry) {
    int ret;

    if (!old_dentry || !old_dentry->d_inode || !dir || !new_dentry)
        return -EINVAL;
    if (S_ISDIR(old_dentry->d_inode->i_mode))
        return -EPERM;
    if (old_dentry->d_inode->i_sb != dir->i_sb)
        return -EXDEV;

    ret =
        devtmpfs_add_dirent(dir, new_dentry->d_name.name, old_dentry->d_inode);
    if (ret < 0)
        return ret;

    old_dentry->d_inode->i_nlink++;
    vfs_d_instantiate(new_dentry, old_dentry->d_inode);
    return 0;
}

static int devtmpfs_unlink(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    devtmpfs_dirent_t *de;

    if (!dir || !dentry || !dentry->d_inode)
        return -ENOENT;
    if (S_ISDIR(dentry->d_inode->i_mode))
        return -EISDIR;

    de = devtmpfs_detach_dirent(dir, dentry->d_name.name);
    if (!de)
        return -ENOENT;

    if (de->inode->i_nlink)
        de->inode->i_nlink--;
    devtmpfs_free_dirent(de);
    return 0;
}

static int devtmpfs_rmdir(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    devtmpfs_dirent_t *de;
    devtmpfs_inode_info_t *info;
    bool has_children;

    if (!dir || !dentry || !dentry->d_inode ||
        !S_ISDIR(dentry->d_inode->i_mode))
        return -ENOTDIR;

    info = devtmpfs_i(dentry->d_inode);
    mutex_lock(&info->lock);
    has_children = !llist_empty(&info->children);
    mutex_unlock(&info->lock);
    if (has_children)
        return -ENOTEMPTY;

    de = devtmpfs_detach_dirent(dir, dentry->d_name.name);
    if (!de)
        return -ENOENT;

    if (dir->i_nlink)
        dir->i_nlink--;
    if (de->inode->i_nlink >= 2)
        de->inode->i_nlink -= 2;
    devtmpfs_free_dirent(de);
    return 0;
}

static int devtmpfs_rename(struct vfs_rename_ctx *ctx) {
    devtmpfs_inode_info_t *old_info;
    devtmpfs_inode_info_t *new_info;
    devtmpfs_dirent_t *old_de;
    devtmpfs_dirent_t *victim = NULL;
    char *new_name;
    char *old_name = NULL;

    if (!ctx || !ctx->old_dir || !ctx->new_dir || !ctx->old_dentry ||
        !ctx->new_dentry)
        return -EINVAL;

    if (ctx->flags & (VFS_RENAME_EXCHANGE | VFS_RENAME_WHITEOUT))
        return -EOPNOTSUPP;

    old_info = devtmpfs_i(ctx->old_dir);
    new_info = devtmpfs_i(ctx->new_dir);
    if (!old_info || !new_info)
        return -EINVAL;

    new_name = strdup(ctx->new_dentry->d_name.name);
    if (!new_name)
        return -ENOMEM;

    devtmpfs_lock_dir_infos(old_info, new_info);
    old_de =
        devtmpfs_find_dirent_locked(old_info, ctx->old_dentry->d_name.name);
    if (!old_de) {
        devtmpfs_unlock_dir_infos(old_info, new_info);
        free(new_name);
        return -ENOENT;
    }
    llist_delete(&old_de->node);

    victim =
        devtmpfs_find_dirent_locked(new_info, ctx->new_dentry->d_name.name);
    if (victim)
        llist_delete(&victim->node);
    if (victim) {
        if (S_ISDIR(victim->inode->i_mode) != S_ISDIR(old_de->inode->i_mode)) {
            llist_init_head(&old_de->node);
            llist_append(&old_info->children, &old_de->node);
            llist_init_head(&victim->node);
            llist_append(&new_info->children, &victim->node);
            devtmpfs_unlock_dir_infos(old_info, new_info);
            free(new_name);
            return -ENOTEMPTY;
        }
    } else if (ctx->flags & VFS_RENAME_NOREPLACE) {
        llist_init_head(&old_de->node);
        llist_append(&old_info->children, &old_de->node);
        devtmpfs_unlock_dir_infos(old_info, new_info);
        free(new_name);
        return -EEXIST;
    }

    old_name = old_de->name;
    old_de->name = new_name;
    llist_init_head(&old_de->node);
    llist_append(&new_info->children, &old_de->node);
    devtmpfs_unlock_dir_infos(old_info, new_info);
    free(old_name);
    devtmpfs_free_dirent(victim);
    return 0;
}

static const char *devtmpfs_get_link(struct vfs_dentry *dentry,
                                     struct vfs_inode *inode,
                                     struct vfs_nameidata *nd) {
    devtmpfs_inode_info_t *info = devtmpfs_i(inode);
    (void)dentry;
    (void)nd;
    return info && info->link_target ? info->link_target : ERR_PTR(-EINVAL);
}

static int devtmpfs_permission(struct vfs_inode *inode, int mask) {
    (void)inode;
    (void)mask;
    return 0;
}

static int devtmpfs_getattr(const struct vfs_path *path, struct vfs_kstat *stat,
                            uint32_t request_mask, unsigned int flags) {
    (void)request_mask;
    (void)flags;
    vfs_fill_generic_kstat(path, stat);
    return 0;
}

static int devtmpfs_setattr(struct vfs_dentry *dentry,
                            const struct vfs_kstat *stat) {
    int ret = 0;

    if (!dentry || !dentry->d_inode || !stat)
        return -EINVAL;

    if (stat->mode)
        dentry->d_inode->i_mode = stat->mode;
    dentry->d_inode->i_uid = stat->uid;
    dentry->d_inode->i_gid = stat->gid;
    if (!S_ISDIR(dentry->d_inode->i_mode) &&
        !S_ISCHR(dentry->d_inode->i_mode) &&
        !S_ISBLK(dentry->d_inode->i_mode) &&
        stat->size != dentry->d_inode->i_size) {
        ret = devtmpfs_resize_inode(dentry->d_inode, stat->size);
    }
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

static loff_t devtmpfs_llseek(struct vfs_file *file, loff_t offset,
                              int whence) {
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

static ssize_t devtmpfs_read(struct vfs_file *file, void *buf, size_t count,
                             loff_t *ppos) {
    devtmpfs_inode_info_t *info;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;
    if (S_ISCHR(file->f_inode->i_mode) || S_ISBLK(file->f_inode->i_mode))
        return device_read(file->f_inode->i_rdev, buf, (uint64_t)*ppos, count,
                           file);

    info = devtmpfs_i(file->f_inode);
    if (!info)
        return -EINVAL;

    mutex_lock(&info->lock);
    ssize_t ret = paged_file_store_read_locked(&info->store, buf, count, ppos);
    mutex_unlock(&info->lock);
    return ret;
}

static ssize_t devtmpfs_write(struct vfs_file *file, const void *buf,
                              size_t count, loff_t *ppos) {
    devtmpfs_inode_info_t *info;
    uint64_t end;
    ssize_t ret;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;
    if (S_ISCHR(file->f_inode->i_mode) || S_ISBLK(file->f_inode->i_mode))
        return device_write(file->f_inode->i_rdev, (void *)buf, (uint64_t)*ppos,
                            count, file);

    info = devtmpfs_i(file->f_inode);
    if (*ppos < 0)
        return -EINVAL;
    if ((uint64_t)*ppos > UINT64_MAX - count)
        return -EFBIG;

    end = (uint64_t)*ppos + count;
    ret = devtmpfs_resize_inode(file->f_inode, MAX(info->store.size, end));
    if (ret < 0)
        return ret;

    mutex_lock(&info->lock);
    ret = paged_file_store_write_locked(&info->store, buf, count, ppos);
    if (ret > 0 && end > info->store.size)
        info->store.size = end;
    file->f_inode->i_size = info->store.size;
    file->f_inode->i_version++;
    mutex_unlock(&info->lock);
    return ret;
}

static int devtmpfs_iterate_shared(struct vfs_file *file,
                                   struct vfs_dir_context *ctx) {
    devtmpfs_inode_info_t *info;
    devtmpfs_dirent_t *de, *tmp;
    loff_t index = 0;

    if (!file || !file->f_inode || !ctx || !S_ISDIR(file->f_inode->i_mode))
        return -ENOTDIR;

    devtmpfs_ensure_populated(file->f_inode->i_sb);

    info = devtmpfs_i(file->f_inode);
    mutex_lock(&info->lock);
    llist_for_each(de, tmp, &info->children, node) {
        if (index++ < ctx->pos)
            continue;
        if (ctx->actor(ctx, de->name, (int)strlen(de->name), index,
                       de->inode->i_ino, devtmpfs_dtype(de->inode->i_mode))) {
            break;
        }
        ctx->pos = index;
    }
    mutex_unlock(&info->lock);

    file->f_pos = ctx->pos;
    return 0;
}

static int devtmpfs_open_file(struct vfs_inode *inode, struct vfs_file *file) {
    ssize_t ret;

    if (!inode || !file)
        return -EINVAL;
    if (S_ISDIR(inode->i_mode))
        devtmpfs_ensure_populated(inode->i_sb);
    if ((file->f_flags & O_PATH) == 0 &&
        (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))) {
        ret = device_open(inode->i_rdev, NULL);
        if (ret < 0)
            return (int)ret;
    }
    file->f_op = inode->i_fop;
    return 0;
}

static int devtmpfs_release_file(struct vfs_inode *inode,
                                 struct vfs_file *file) {
    (void)file;
    if (inode && (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)))
        device_close(inode->i_rdev);
    return 0;
}

static long devtmpfs_ioctl(struct vfs_file *file, unsigned long cmd,
                           unsigned long arg) {
    if (!file || !file->f_inode)
        return -EINVAL;
    if (S_ISCHR(file->f_inode->i_mode) || S_ISBLK(file->f_inode->i_mode))
        return device_ioctl(file->f_inode->i_rdev, (int)cmd, (void *)arg, file);
    return -EINVAL;
}

static void *devtmpfs_mmap(struct vfs_file *file, void *addr, size_t offset,
                           size_t size, size_t prot, uint64_t flags) {
    devtmpfs_inode_info_t *info;
    uint64_t pt_flags = PT_FLAG_U;
    uint64_t *pgdir;
    int ret;

    if (!file || !file->f_inode)
        return (void *)(int64_t)-EINVAL;
    if (S_ISCHR(file->f_inode->i_mode) || S_ISBLK(file->f_inode->i_mode)) {
        return device_map(file->f_inode->i_rdev, addr, offset, size, prot,
                          file);
    }
    if (!S_ISREG(file->f_inode->i_mode))
        return (void *)(int64_t)-ENODEV;
    if ((flags & MAP_TYPE) == MAP_PRIVATE)
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);
    if (offset > SIZE_MAX - size)
        return (void *)(int64_t)-EINVAL;

    info = devtmpfs_i(file->f_inode);
    if (!info)
        return (void *)(int64_t)-EINVAL;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;
    if (!(pt_flags & (PT_FLAG_R | PT_FLAG_W | PT_FLAG_X)))
        pt_flags |= PT_FLAG_R;

    pgdir = get_current_page_dir(true);
    mutex_lock(&info->lock);
    ret = paged_file_store_map_shared_locked(&info->store, pgdir,
                                             (uint64_t)addr, (uint64_t)offset,
                                             (uint64_t)size, pt_flags);
    mutex_unlock(&info->lock);
    if (ret < 0)
        return (void *)(int64_t)ret;

    return addr;
}

static __poll_t devtmpfs_poll_file(struct vfs_file *file,
                                   struct vfs_poll_table *pt) {
    (void)pt;
    if (!file || !file->f_inode)
        return EPOLLNVAL;
    if (S_ISCHR(file->f_inode->i_mode) || S_ISBLK(file->f_inode->i_mode))
        return (__poll_t)device_poll(file->f_inode->i_rdev,
                                     EPOLLIN | EPOLLOUT | EPOLLPRI);
    return EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM;
}

static struct vfs_inode *devtmpfs_alloc_inode(struct vfs_super_block *sb) {
    devtmpfs_inode_info_t *info = calloc(1, sizeof(*info));

    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void devtmpfs_destroy_inode(struct vfs_inode *inode) {
    free(devtmpfs_i(inode));
}

static void devtmpfs_evict_inode(struct vfs_inode *inode) {
    devtmpfs_inode_info_t *info = devtmpfs_i(inode);
    devtmpfs_dirent_t *de, *tmp;

    if (!info)
        return;
    tmpfs_mem_release(info->store.size);
    paged_file_store_destroy(&info->store);
    free(info->link_target);
    mutex_lock(&info->lock);
    llist_for_each(de, tmp, &info->children, node) {
        llist_delete(&de->node);
        devtmpfs_free_dirent(de);
    }
    mutex_unlock(&info->lock);
}

static int devtmpfs_init_fs_context(struct vfs_fs_context *fc) {
    if (!fc)
        return -EINVAL;
    fc->fs_private = calloc(1, sizeof(devtmpfs_fs_info_t));
    if (!fc->fs_private)
        return -ENOMEM;
    mutex_init(&((devtmpfs_fs_info_t *)fc->fs_private)->populate_lock);
    return 0;
}

static int devtmpfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    devtmpfs_fs_info_t *fsi;
    vfs_node_t *root_inode;
    struct vfs_dentry *root_dentry;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};

    if (!fc)
        return -EINVAL;

    fsi = fc->fs_private;
    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb) {
        free(fsi);
        return -ENOMEM;
    }

    sb->s_op = &devtmpfs_super_ops;
    sb->s_type = &devtmpfs_fs_type;
    sb->s_magic = DEVTMPFS_MAGIC;
    sb->s_fs_info = fsi;
    fc->fs_private = NULL;

    root_inode = devtmpfs_new_inode(sb, S_IFDIR | 0755);
    if (!root_inode) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    root_dentry = vfs_d_alloc(sb, NULL, &root_name);
    if (!root_dentry) {
        vfs_iput(root_inode);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root_dentry, root_inode);
    sb->s_root = root_dentry;
    fc->sb = sb;
    return 0;
}

static void devtmpfs_put_super(struct vfs_super_block *sb) {
    if (!sb || !sb->s_fs_info)
        return;
    free(sb->s_fs_info);
    sb->s_fs_info = NULL;
}

static const struct vfs_super_operations devtmpfs_super_ops = {
    .alloc_inode = devtmpfs_alloc_inode,
    .destroy_inode = devtmpfs_destroy_inode,
    .evict_inode = devtmpfs_evict_inode,
    .put_super = devtmpfs_put_super,
};

static const struct vfs_inode_operations devtmpfs_inode_ops = {
    .lookup = devtmpfs_lookup,
    .create = devtmpfs_create,
    .link = devtmpfs_link,
    .unlink = devtmpfs_unlink,
    .symlink = devtmpfs_symlink,
    .mkdir = devtmpfs_mkdir,
    .rmdir = devtmpfs_rmdir,
    .mknod = devtmpfs_mknod,
    .rename = devtmpfs_rename,
    .get_link = devtmpfs_get_link,
    .permission = devtmpfs_permission,
    .getattr = devtmpfs_getattr,
    .setattr = devtmpfs_setattr,
};

static const struct vfs_file_operations devtmpfs_dir_file_ops = {
    .llseek = devtmpfs_llseek,
    .iterate_shared = devtmpfs_iterate_shared,
    .open = devtmpfs_open_file,
    .release = devtmpfs_release_file,
    .poll = devtmpfs_poll_file,
};

static const struct vfs_file_operations devtmpfs_file_ops = {
    .llseek = devtmpfs_llseek,
    .read = devtmpfs_read,
    .write = devtmpfs_write,
    .unlocked_ioctl = devtmpfs_ioctl,
    .mmap = devtmpfs_mmap,
    .open = devtmpfs_open_file,
    .release = devtmpfs_release_file,
    .poll = devtmpfs_poll_file,
};

static struct vfs_file_system_type devtmpfs_fs_type = {
    .name = "devtmpfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = devtmpfs_init_fs_context,
    .get_tree = devtmpfs_get_tree,
};

static vfs_node_t *devtmpfs_lookup_inode_path(const char *path,
                                              unsigned int lookup_flags) {
    struct vfs_path p = {0};
    vfs_node_t *inode = NULL;

    if (!path)
        return NULL;
    if (vfs_filename_lookup(AT_FDCWD, path, lookup_flags, &p) < 0)
        return NULL;
    if (p.dentry && p.dentry->d_inode)
        inode = vfs_igrab(p.dentry->d_inode);
    vfs_path_put(&p);
    return inode;
}

static void devtmpfs_refresh_root(void) {
    vfs_node_t *root = devtmpfs_lookup_inode_path("/dev", LOOKUP_FOLLOW);

    if (!root)
        return;
    if (devtmpfs_root)
        vfs_iput(devtmpfs_root);
    devtmpfs_root = root;
}

static void devfs_ensure_parent_dirs(const char *path) {
    char *copy;
    char *slash;

    if (!path || path[0] != '/')
        return;

    copy = strdup(path);
    if (!copy)
        return;

    for (slash = copy + 1; (slash = strchr(slash, '/')) != NULL; slash++) {
        *slash = '\0';
        (void)vfs_mkdirat(AT_FDCWD, copy, 0755);
        *slash = '/';
    }

    free(copy);
}

static void devfs_register_existing_devices(void) {
    int subtype;

    for (subtype = 0; subtype < DEV_MAX; subtype++) {
        uint64_t index = 0;

        while (true) {
            device_t *device = device_find(subtype, index++);
            if (!device)
                break;
            devfs_register_device(device);
        }
    }
}

static void devtmpfs_populate_nodes(void) {
    pty_init();

    (void)vfs_mkdirat(AT_FDCWD, "/dev/shm", 0755);
    (void)vfs_mkdirat(AT_FDCWD, "/dev/bus", 0755);
    (void)vfs_mkdirat(AT_FDCWD, "/dev/bus/usb", 0755);

    devfs_initialized = true;
    devfs_register_existing_devices();
    setup_console_symlinks();
    ptmx_init();
    pts_init();
    pts_repopulate_nodes();

    devtmpfs_refresh_root();
}

static void devtmpfs_ensure_populated(struct vfs_super_block *sb) {
    devtmpfs_fs_info_t *fsi = devtmpfs_sb_info(sb);

    if (!fsi)
        return;

    mutex_lock(&fsi->populate_lock);
    if (fsi->populated || fsi->populating) {
        mutex_unlock(&fsi->populate_lock);
        return;
    }
    fsi->populating = true;
    mutex_unlock(&fsi->populate_lock);

    devtmpfs_populate_nodes();

    mutex_lock(&fsi->populate_lock);
    fsi->populating = false;
    fsi->populated = true;
    mutex_unlock(&fsi->populate_lock);
}

ssize_t inputdev_open(void *data, void *arg) {
    dev_input_event_t *event = data;
    (void)arg;
    event->timesOpened++;
    return 0;
}

ssize_t inputdev_close(void *data, void *arg) {
    dev_input_event_t *event = data;
    (void)arg;
    if (event->timesOpened > 0)
        event->timesOpened--;
    return 0;
}

static int inputdev_wait_node(vfs_node_t *node, uint32_t events,
                              const char *reason) {
    if (!node || !current_task)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    int polled = vfs_poll(node, want);
    if (polled < 0)
        return polled;
    if (polled & (int)want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(node, &wait) < 0)
        return -EINVAL;

    polled = vfs_poll(node, want);
    if (polled < 0) {
        vfs_poll_wait_disarm(&wait);
        return polled;
    }
    if (polled & (int)want) {
        vfs_poll_wait_disarm(&wait);
        return EOK;
    }

    int ret = vfs_poll_wait_sleep(node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
}

static bool input_event_queue_push(dev_input_event_t *event,
                                   const struct input_event *in) {
    if (!event || !in || !event->event_queue || !event->event_queue_capacity)
        return false;

    spin_lock(&event->event_queue_lock);

    if (event->event_queue_count >= event->event_queue_capacity) {
        event->event_queue_head =
            (event->event_queue_head + 1) % event->event_queue_capacity;
        event->event_queue_count--;
        event->event_queue_overflow = true;
    }

    event->event_queue[event->event_queue_tail] = *in;
    event->event_queue_tail =
        (event->event_queue_tail + 1) % event->event_queue_capacity;
    event->event_queue_count++;

    spin_unlock(&event->event_queue_lock);
    return true;
}

static size_t input_event_queue_pop(dev_input_event_t *event,
                                    struct input_event *out,
                                    size_t max_events) {
    if (!event || !out || max_events == 0)
        return 0;

    size_t produced = 0;
    spin_lock(&event->event_queue_lock);

    if (event->event_queue_overflow && produced < max_events) {
        memset(&out[produced], 0, sizeof(struct input_event));
        uint64_t now_ns = nano_time();
        out[produced].sec = now_ns / 1000000000ULL;
        out[produced].usec = (now_ns % 1000000000ULL) / 1000ULL;
        out[produced].type = EV_SYN;
        out[produced].code = 3;
        out[produced].value = 0;
        event->event_queue_overflow = false;
        produced++;
    }

    while (produced < max_events && event->event_queue_count > 0 &&
           event->event_queue_capacity > 0) {
        out[produced++] = event->event_queue[event->event_queue_head];
        event->event_queue_head =
            (event->event_queue_head + 1) % event->event_queue_capacity;
        event->event_queue_count--;
    }

    spin_unlock(&event->event_queue_lock);
    return produced;
}

static bool input_event_queue_has_data(dev_input_event_t *event) {
    bool has_data = false;

    if (!event)
        return false;

    spin_lock(&event->event_queue_lock);
    has_data = (event->event_queue_count > 0) || event->event_queue_overflow;
    spin_unlock(&event->event_queue_lock);
    return has_data;
}

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;
    (void)offset;
    if (!event || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;
    if (len < sizeof(struct input_event))
        return -EINVAL;

    len = (len / sizeof(struct input_event)) * sizeof(struct input_event);
    struct input_event *events = (struct input_event *)buf;
    size_t max_events = len / sizeof(struct input_event);

    while (true) {
        size_t cnt = input_event_queue_pop(event, events, max_events);
        if (cnt > 0)
            return cnt * sizeof(struct input_event);
        if (flags & O_NONBLOCK)
            return -EWOULDBLOCK;
        return 0;
    }
}

ssize_t inputdev_event_write(void *data, const void *buf, uint64_t offset,
                             uint64_t len, uint64_t flags) {
    (void)data;
    (void)buf;
    (void)offset;
    (void)flags;
    return len;
}

ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd) {
    dev_input_event_t *event = data;
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);
    ssize_t ret = -ENOTTY;

    (void)fd;

    if (number >= 0x20 && number < (0x20 + EV_CNT))
        return event->event_bit(data, request, (void *)arg);
    if (number >= 0x40 && number < (0x40 + ABS_CNT))
        return event->event_bit(data, request, (void *)arg);
    if (request == 0x540b)
        return 0;

    switch (number) {
    case 0x01:
        if (!arg || copy_to_user((void *)arg, &(int){0x10001}, sizeof(int)))
            return -EFAULT;
        ret = 0;
        break;
    case 0x02:
        if (!arg ||
            copy_to_user((void *)arg, &event->inputid, sizeof(struct input_id)))
            return -EFAULT;
        ret = 0;
        break;
    case 0x06: {
        int to_copy = MIN(size, (size_t)strlen(event->devname) + 1);
        if (to_copy && (!arg || copy_to_user((void *)arg, event->devname,
                                             (size_t)to_copy)))
            return -EFAULT;
        ret = to_copy;
        break;
    }
    case 0x07: {
        int to_copy = MIN(size, (size_t)strlen(event->physloc) + 1);
        if (to_copy && (!arg || copy_to_user((void *)arg, event->devname,
                                             (size_t)to_copy)))
            return -EFAULT;
        ret = to_copy;
        break;
    }
    case 0x08:
        if (event->uniq[0]) {
            int to_copy = MIN(size, (size_t)strlen(event->uniq) + 1);
            if (to_copy && (!arg || copy_to_user((void *)arg, event->uniq,
                                                 (size_t)to_copy)))
                return -EFAULT;
            ret = to_copy;
        } else {
            ret = -ENODATA;
        }
        break;
    case 0x09:
        if (size) {
            int to_copy = MIN(sizeof(size_t), size);
            if (!arg ||
                copy_to_user((void *)arg, &event->properties, (size_t)to_copy))
                return -EFAULT;
            ret = to_copy;
        } else {
            ret = 0;
        }
        break;
    case 0x03:
    case 0x18:
    case 0x19:
    case 0x1b:
    case 0xa0:
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x91:
        ret = 0;
        break;
    default:
        printk("inputdev_ioctl(): Unsupported ioctl: %#018lx\n", request);
        ret = -ENOTTY;
        break;
    }

    return ret;
}

ssize_t inputdev_poll(void *data, size_t event) {
    dev_input_event_t *e = data;
    if (input_event_queue_has_data(e) && (event & EPOLLIN))
        return EPOLLIN;
    return 0;
}

void devfs_register_device(device_t *device) {
    char path[128];

    if (!devfs_initialized || !device || !device->name)
        return;

    snprintf(path, sizeof(path), "/dev/%s", device->name);
    devfs_ensure_parent_dirs(path);
    vfs_mknodat(AT_FDCWD, path,
                0600 | (device->type == DEV_BLOCK ? S_IFBLK : S_IFCHR),
                device->dev);

    if (device->type == DEV_BLOCK && device->ptr) {
        vfs_node_t *inode = devtmpfs_lookup_inode_path(path, LOOKUP_FOLLOW);
        partition_t *part = device->ptr;
        if (!inode)
            return;
        inode->i_size = 512ULL * (part->ending_lba - part->starting_lba + 1);
        vfs_iput(inode);
    }
}

void devfs_unregister_device(device_t *device) {
    char path[128];

    if (!devfs_initialized || !device || !device->name || !device->name[0])
        return;

    snprintf(path, sizeof(path), "/dev/%s", device->name);
    vfs_unlinkat(AT_FDCWD, path, 0);
}

void devtmpfs_init() {
    vfs_register_filesystem(&devtmpfs_fs_type);
    vfs_mkdirat(AT_FDCWD, "/dev", 0755);
    vfs_do_mount(AT_FDCWD, "/dev", "devtmpfs", 0, NULL, NULL);
    devtmpfs_refresh_root();
}

void devtmpfs_init_umount() {
    vfs_do_umount(AT_FDCWD, "/dev", 0);
    if (devtmpfs_root) {
        vfs_iput(devtmpfs_root);
        devtmpfs_root = NULL;
    }
}

ssize_t nulldev_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    (void)data;
    (void)buf;
    (void)offset;
    (void)len;
    (void)flags;
    return 0;
}

ssize_t nulldev_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    (void)data;
    (void)offset;
    (void)flags;
    serial_printk(buf, len);
    return len;
}

ssize_t nulldev_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd) {
    (void)data;
    (void)request;
    (void)arg;
    (void)fd;
    return 0;
}

static uint64_t simple_rand() {
    uint32_t seed = boot_get_boottime() * 100 + nano_time() / 10;
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return ((uint64_t)seed << 32) | seed;
}

ssize_t zerodev_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    (void)data;
    (void)offset;
    (void)flags;
    memset(buf, 0, len);
    return len;
}

ssize_t zerodev_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    (void)data;
    (void)buf;
    (void)offset;
    (void)len;
    (void)flags;
    return 0;
}

ssize_t zerodev_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd) {
    (void)data;
    (void)request;
    (void)arg;
    (void)fd;
    return 0;
}

ssize_t urandom_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    (void)data;
    (void)offset;
    (void)flags;
    for (uint64_t i = 0; i < len; i++) {
        uint64_t rand = simple_rand();
        uint8_t byte = (rand >> 5) & 0xFF;
        if (copy_to_user((char *)buf + i, &byte, 1))
            return -EFAULT;
    }
    return len;
}

ssize_t urandom_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    (void)data;
    (void)buf;
    (void)offset;
    (void)len;
    (void)flags;
    return 0;
}

ssize_t urandom_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd) {
    (void)data;
    (void)request;
    (void)arg;
    (void)fd;
    return 0;
}

extern char *default_console;

void setup_console_symlinks() {
    vfs_node_t *tty_node =
        devtmpfs_lookup_inode_path(default_console, LOOKUP_FOLLOW);
    vfs_node_t *tty0_node;

    if (!tty_node)
        return;

    vfs_mknodat(AT_FDCWD, "/dev/console", 0600 | S_IFCHR, tty_node->i_rdev);
    vfs_mknodat(AT_FDCWD, "/dev/tty", 0600 | S_IFCHR, tty_node->i_rdev);
    tty0_node = devtmpfs_lookup_inode_path("/dev/tty0", LOOKUP_FOLLOW);
    if (!tty0_node)
        vfs_mknodat(AT_FDCWD, "/dev/tty0", 0600 | S_IFCHR, tty_node->i_rdev);
    else
        vfs_iput(tty0_node);
    vfs_mknodat(AT_FDCWD, "/dev/tty1", 0600 | S_IFCHR, tty_node->i_rdev);
    vfs_mknodat(AT_FDCWD, "/dev/stdin", 0600 | S_IFCHR, tty_node->i_rdev);
    vfs_mknodat(AT_FDCWD, "/dev/stdout", 0600 | S_IFCHR, tty_node->i_rdev);
    vfs_mknodat(AT_FDCWD, "/dev/stderr", 0600 | S_IFCHR, tty_node->i_rdev);
    vfs_mknodat(AT_FDCWD, "/dev/kmsg", 0600 | S_IFCHR, tty_node->i_rdev);

    vfs_iput(tty_node);
}

void devfs_nodes_init() {
    vfs_mkdirat(AT_FDCWD, "/dev/shm", 0755);
    vfs_mkdirat(AT_FDCWD, "/dev/bus", 0755);
    vfs_mkdirat(AT_FDCWD, "/dev/bus/usb", 0755);

    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "null", 0, NULL, NULL,
                   nulldev_ioctl, NULL, nulldev_read, nulldev_write, NULL);
    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "zero", 0, NULL, NULL, NULL,
                   zerodev_ioctl, zerodev_read, zerodev_write, NULL);
    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "urandom", 0, NULL, NULL, NULL,
                   urandom_ioctl, urandom_read, urandom_write, NULL);

    setup_console_symlinks();

    pty_init();
    ptmx_init();
    pts_init();
}

void input_generate_event(void *data, uint16_t type, uint16_t code,
                          int32_t value, uint64_t sec, uint64_t usecs) {
    dev_input_event_t *item = data;
    if (!item || item->timesOpened == 0)
        return;

    struct input_event event;
    memset(&event, 0, sizeof(struct input_event));
    event.sec = sec;
    event.usec = usecs;
    event.type = type;
    event.code = code;
    event.value = value;

    bool queued = input_event_queue_push(item, &event);
    if (type == EV_SYN && code == SYN_REPORT && queued && item->devnode)
        vfs_poll_notify(item->devnode, EPOLLIN);
}
