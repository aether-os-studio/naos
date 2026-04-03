#include <fs/cgroup/cgroupfs.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/tmpfs_limit.h>

typedef struct cgroupfs_dirent {
    struct llist_header node;
    char *name;
    struct vfs_inode *inode;
} cgroupfs_dirent_t;

typedef struct cgroupfs_inode_info {
    struct vfs_inode vfs_inode;
    struct llist_header children;
    char *content;
    size_t size;
    size_t capacity;
} cgroupfs_inode_info_t;

static struct vfs_file_system_type cgroupfs_fs_type;
static const struct vfs_super_operations cgroupfs_super_ops;
static const struct vfs_inode_operations cgroupfs_inode_ops;
static const struct vfs_file_operations cgroupfs_dir_file_ops;
static const struct vfs_file_operations cgroupfs_file_ops;

static inline cgroupfs_inode_info_t *cgroupfs_i(struct vfs_inode *inode) {
    return inode ? container_of(inode, cgroupfs_inode_info_t, vfs_inode) : NULL;
}

static struct vfs_inode *cgroupfs_alloc_inode(struct vfs_super_block *sb) {
    cgroupfs_inode_info_t *info = calloc(1, sizeof(*info));
    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void cgroupfs_destroy_inode(struct vfs_inode *inode) {
    free(cgroupfs_i(inode));
}

static void cgroupfs_evict_inode(struct vfs_inode *inode) {
    cgroupfs_inode_info_t *info = cgroupfs_i(inode);
    cgroupfs_dirent_t *de, *tmp;

    if (!info)
        return;
    if (info->content && info->capacity) {
        tmpfs_mem_release(info->capacity);
        free_frames_bytes(info->content, info->capacity);
    }
    llist_for_each(de, tmp, &info->children, node) {
        llist_delete(&de->node);
        if (de->inode)
            vfs_iput(de->inode);
        free(de->name);
        free(de);
    }
}

static int cgroupfs_resize(struct vfs_inode *inode, uint64_t new_size) {
    cgroupfs_inode_info_t *info = cgroupfs_i(inode);
    uint64_t old_capacity = info->capacity;
    uint64_t new_capacity = new_size ? tmpfs_mem_align(new_size) : 0;
    void *new_data = NULL;
    int ret;

    if (!info || S_ISDIR(inode->i_mode))
        return -EINVAL;
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
        if (info->content && info->size)
            memcpy(new_data, info->content, MIN(info->size, new_capacity));
    }

    if (info->content && old_capacity)
        free_frames_bytes(info->content, old_capacity);

    info->content = new_data;
    info->capacity = new_capacity;
    info->size = new_size;
    inode->i_size = new_size;
    return 0;
}

static struct vfs_inode *cgroupfs_new_inode(struct vfs_super_block *sb,
                                            umode_t mode) {
    struct vfs_inode *inode = vfs_alloc_inode(sb);
    cgroupfs_inode_info_t *info = cgroupfs_i(inode);

    if (!inode)
        return NULL;
    llist_init_head(&info->children);
    inode->i_op = &cgroupfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &cgroupfs_dir_file_ops : &cgroupfs_file_ops;
    inode->i_mode = mode;
    inode->i_nlink = S_ISDIR(mode) ? 2 : 1;
    inode->type = S_ISDIR(mode) ? file_dir : file_none;
    inode->i_ino = (ino64_t)(uintptr_t)inode;
    inode->inode = inode->i_ino;
    inode->i_blkbits = 12;
    return inode;
}

static cgroupfs_dirent_t *cgroupfs_find_dirent(struct vfs_inode *dir,
                                               const char *name) {
    cgroupfs_inode_info_t *info = cgroupfs_i(dir);
    cgroupfs_dirent_t *de, *tmp;

    llist_for_each(de, tmp, &info->children, node) {
        if (de->name && streq(de->name, name))
            return de;
    }
    return NULL;
}

static int cgroupfs_add_dirent(struct vfs_inode *dir, const char *name,
                               struct vfs_inode *inode) {
    cgroupfs_dirent_t *de = calloc(1, sizeof(*de));
    if (!de)
        return -ENOMEM;
    de->name = strdup(name);
    if (!de->name) {
        free(de);
        return -ENOMEM;
    }
    de->inode = vfs_igrab(inode);
    llist_init_head(&de->node);
    llist_append(&cgroupfs_i(dir)->children, &de->node);
    return 0;
}

static int cgroupfs_write_string(struct vfs_inode *inode, const char *content) {
    size_t len = content ? strlen(content) : 0;
    int ret = cgroupfs_resize(inode, len);
    if (ret < 0)
        return ret;
    if (len)
        memcpy(cgroupfs_i(inode)->content, content, len);
    return 0;
}

static int cgroupfs_create_file_with_content(struct vfs_inode *dir,
                                             const char *name,
                                             const char *content) {
    struct vfs_inode *inode = cgroupfs_new_inode(dir->i_sb, S_IFREG | 0644);
    int ret;

    if (!inode)
        return -ENOMEM;
    ret = cgroupfs_resize(inode, MAX((size_t)PAGE_SIZE, strlen(content)));
    if (ret < 0) {
        vfs_iput(inode);
        return ret;
    }
    ret = cgroupfs_write_string(inode, content);
    if (ret == 0)
        ret = cgroupfs_add_dirent(dir, name, inode);
    vfs_iput(inode);
    return ret;
}

static int cgroupfs_populate_dir(struct vfs_inode *dir) {
    if (cgroupfs_create_file_with_content(dir, "cgroup.procs", "") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.threads", "") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.controllers",
                                          "cpu io memory pids\n") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.events",
                                          "populated 1\nfrozen 0\n") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.type", "domain\n") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.freeze", "0\n") < 0)
        return -ENOMEM;
    if (cgroupfs_create_file_with_content(dir, "cgroup.subtree_control", "\n") <
        0)
        return -ENOMEM;
    return 0;
}

static struct vfs_dentry *cgroupfs_lookup(struct vfs_inode *dir,
                                          struct vfs_dentry *dentry,
                                          unsigned int flags) {
    cgroupfs_dirent_t *de;
    (void)flags;
    de = cgroupfs_find_dirent(dir, dentry->d_name.name);
    vfs_d_instantiate(dentry, de ? de->inode : NULL);
    return dentry;
}

static int cgroupfs_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                          umode_t mode) {
    struct vfs_inode *inode =
        cgroupfs_new_inode(dir->i_sb, (mode & 07777) | S_IFDIR);
    int ret;

    if (!inode)
        return -ENOMEM;
    ret = cgroupfs_populate_dir(inode);
    if (ret == 0)
        ret = cgroupfs_add_dirent(dir, dentry->d_name.name, inode);
    if (ret == 0) {
        dir->i_nlink++;
        vfs_d_instantiate(dentry, inode);
    }
    vfs_iput(inode);
    return ret;
}

static int cgroupfs_iterate_shared(struct vfs_file *file,
                                   struct vfs_dir_context *ctx) {
    cgroupfs_dirent_t *de, *tmp;
    loff_t index = 0;

    llist_for_each(de, tmp, &cgroupfs_i(file->f_inode)->children, node) {
        if (index++ < ctx->pos)
            continue;
        if (ctx->actor(ctx, de->name, (int)strlen(de->name), index,
                       de->inode->i_ino,
                       S_ISDIR(de->inode->i_mode) ? DT_DIR : DT_REG)) {
            break;
        }
        ctx->pos = index;
    }
    file->f_pos = ctx->pos;
    return 0;
}

static ssize_t cgroupfs_read(struct vfs_file *file, void *buf, size_t count,
                             loff_t *ppos) {
    cgroupfs_inode_info_t *info = cgroupfs_i(file->f_inode);
    size_t pos = (size_t)*ppos;
    size_t to_copy;

    if (pos >= info->size)
        return 0;
    to_copy = MIN(count, info->size - pos);
    memcpy(buf, info->content + pos, to_copy);
    *ppos += (loff_t)to_copy;
    return (ssize_t)to_copy;
}

static ssize_t cgroupfs_write(struct vfs_file *file, const void *buf,
                              size_t count, loff_t *ppos) {
    cgroupfs_inode_info_t *info = cgroupfs_i(file->f_inode);
    uint64_t end = (uint64_t)*ppos + count;
    int ret = cgroupfs_resize(file->f_inode, MAX((uint64_t)info->size, end));
    if (ret < 0)
        return ret;
    memcpy(info->content + *ppos, buf, count);
    info->size = MAX(info->size, (size_t)end);
    file->f_inode->i_size = info->size;
    *ppos += (loff_t)count;
    return (ssize_t)count;
}

static int cgroupfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    file->f_op = inode->i_fop;
    return 0;
}

static int cgroupfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int cgroupfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    struct vfs_inode *root_inode;
    struct vfs_dentry *root_dentry;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};
    int ret;

    if (!sb)
        return -ENOMEM;
    sb->s_op = &cgroupfs_super_ops;
    sb->s_magic = 0x63677270;
    sb->s_type = &cgroupfs_fs_type;

    root_inode = cgroupfs_new_inode(sb, S_IFDIR | 0755);
    if (!root_inode) {
        vfs_put_super(sb);
        return -ENOMEM;
    }
    ret = cgroupfs_populate_dir(root_inode);
    if (ret < 0) {
        vfs_iput(root_inode);
        vfs_put_super(sb);
        return ret;
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
    vfs_iput(root_inode);
    return 0;
}

static const struct vfs_super_operations cgroupfs_super_ops = {
    .alloc_inode = cgroupfs_alloc_inode,
    .destroy_inode = cgroupfs_destroy_inode,
    .evict_inode = cgroupfs_evict_inode,
};

static const struct vfs_inode_operations cgroupfs_inode_ops = {
    .lookup = cgroupfs_lookup,
    .mkdir = cgroupfs_mkdir,
};

static const struct vfs_file_operations cgroupfs_dir_file_ops = {
    .iterate_shared = cgroupfs_iterate_shared,
    .open = cgroupfs_open,
};

static const struct vfs_file_operations cgroupfs_file_ops = {
    .read = cgroupfs_read,
    .write = cgroupfs_write,
    .open = cgroupfs_open,
};

static struct vfs_file_system_type cgroupfs_fs_type = {
    .name = "cgroup2",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = cgroupfs_init_fs_context,
    .get_tree = cgroupfs_get_tree,
};

void cgroupfs_init() {
    vfs_register_filesystem(&cgroupfs_fs_type);
    vfs_mkdirat(AT_FDCWD, "/sys/fs/cgroup", 0755);
    vfs_do_mount(AT_FDCWD, "/sys/fs/cgroup", "cgroup2", 0, NULL, NULL);
}
