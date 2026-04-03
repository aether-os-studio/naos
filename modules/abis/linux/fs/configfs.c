#include <fs/configfs.h>
#include <fs/vfs/vfs.h>
#include <mm/mm.h>

typedef struct configfs_inode_info {
    struct vfs_inode vfs_inode;
    struct llist_header children;
} configfs_inode_info_t;

typedef struct configfs_dirent {
    struct llist_header node;
    char *name;
    struct vfs_inode *inode;
} configfs_dirent_t;

static struct vfs_file_system_type configfs_fs_type;
static const struct vfs_super_operations configfs_super_ops;
static const struct vfs_inode_operations configfs_inode_ops;
static const struct vfs_file_operations configfs_dir_file_ops;

static inline configfs_inode_info_t *configfs_i(struct vfs_inode *inode) {
    return inode ? container_of(inode, configfs_inode_info_t, vfs_inode) : NULL;
}

static struct vfs_inode *configfs_alloc_inode(struct vfs_super_block *sb) {
    configfs_inode_info_t *info = malloc(sizeof(*info));
    (void)sb;
    if (info)
        memset(info, 0, sizeof(*info));
    return info ? &info->vfs_inode : NULL;
}

static void configfs_destroy_inode(struct vfs_inode *inode) {
    free(configfs_i(inode));
}

static void configfs_evict_inode(struct vfs_inode *inode) {
    configfs_inode_info_t *info = configfs_i(inode);
    configfs_dirent_t *de, *tmp;

    if (!info)
        return;
    llist_for_each(de, tmp, &info->children, node) {
        llist_delete(&de->node);
        if (de->inode)
            vfs_iput(de->inode);
        free(de->name);
        free(de);
    }
}

static struct vfs_inode *configfs_new_inode(struct vfs_super_block *sb,
                                            umode_t mode) {
    struct vfs_inode *inode = vfs_alloc_inode(sb);
    configfs_inode_info_t *info = configfs_i(inode);

    if (!inode)
        return NULL;
    llist_init_head(&info->children);
    inode->i_op = &configfs_inode_ops;
    inode->i_fop = &configfs_dir_file_ops;
    inode->i_mode = mode;
    inode->i_nlink = 2;
    inode->type = file_dir;
    inode->i_ino = (ino64_t)(uintptr_t)inode;
    inode->inode = inode->i_ino;
    inode->i_blkbits = 12;
    return inode;
}

static configfs_dirent_t *configfs_find_dirent(struct vfs_inode *dir,
                                               const char *name) {
    configfs_inode_info_t *info = configfs_i(dir);
    configfs_dirent_t *de, *tmp;

    llist_for_each(de, tmp, &info->children, node) {
        if (de->name && streq(de->name, name))
            return de;
    }
    return NULL;
}

static struct vfs_dentry *configfs_lookup(struct vfs_inode *dir,
                                          struct vfs_dentry *dentry,
                                          unsigned int flags) {
    configfs_dirent_t *de;
    (void)flags;
    de = configfs_find_dirent(dir, dentry->d_name.name);
    vfs_d_instantiate(dentry, de ? de->inode : NULL);
    return dentry;
}

static int configfs_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                          umode_t mode) {
    struct vfs_inode *inode;
    configfs_dirent_t *de;

    if (configfs_find_dirent(dir, dentry->d_name.name))
        return -EEXIST;

    inode = configfs_new_inode(dir->i_sb, (mode & 07777) | S_IFDIR);
    if (!inode)
        return -ENOMEM;

    de = malloc(sizeof(*de));
    if (!de) {
        vfs_iput(inode);
        return -ENOMEM;
    }
    memset(de, 0, sizeof(*de));
    de->name = strdup(dentry->d_name.name);
    de->inode = vfs_igrab(inode);
    llist_init_head(&de->node);
    llist_append(&configfs_i(dir)->children, &de->node);
    dir->i_nlink++;
    vfs_d_instantiate(dentry, inode);
    vfs_iput(inode);
    return 0;
}

static int configfs_iterate_shared(struct vfs_file *file,
                                   struct vfs_dir_context *ctx) {
    configfs_inode_info_t *info = configfs_i(file->f_inode);
    configfs_dirent_t *de, *tmp;
    loff_t index = 0;

    llist_for_each(de, tmp, &info->children, node) {
        if (index++ < ctx->pos)
            continue;
        if (ctx->actor(ctx, de->name, (int)strlen(de->name), index,
                       de->inode->i_ino, DT_DIR))
            break;
        ctx->pos = index;
    }
    file->f_pos = ctx->pos;
    return 0;
}

static int configfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    (void)inode;
    file->f_op = &configfs_dir_file_ops;
    return 0;
}

static int configfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int configfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    struct vfs_inode *root_inode;
    struct vfs_dentry *root_dentry;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};

    if (!sb)
        return -ENOMEM;
    sb->s_op = &configfs_super_ops;
    sb->s_magic = 0x62656570;
    sb->s_type = &configfs_fs_type;

    root_inode = configfs_new_inode(sb, S_IFDIR | 0755);
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
    vfs_iput(root_inode);
    return 0;
}

static const struct vfs_super_operations configfs_super_ops = {
    .alloc_inode = configfs_alloc_inode,
    .destroy_inode = configfs_destroy_inode,
    .evict_inode = configfs_evict_inode,
};

static const struct vfs_inode_operations configfs_inode_ops = {
    .lookup = configfs_lookup,
    .mkdir = configfs_mkdir,
};

static const struct vfs_file_operations configfs_dir_file_ops = {
    .iterate_shared = configfs_iterate_shared,
    .open = configfs_open,
};

static struct vfs_file_system_type configfs_fs_type = {
    .name = "configfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = configfs_init_fs_context,
    .get_tree = configfs_get_tree,
};

void configfs_init() {
    vfs_register_filesystem(&configfs_fs_type);
    vfs_mkdirat(AT_FDCWD, "/sys/kernel/config", 0755);
    vfs_do_mount(AT_FDCWD, "/sys/kernel/config", "configfs", 0, NULL, NULL);
}
