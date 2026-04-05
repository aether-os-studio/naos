#include "fs/vfs/vfs.h"
#include "fs/vfs/notify.h"
#include "fs/fs_syscall.h"
#include "task/task.h"

struct vfs_mount_namespace vfs_init_mnt_ns = {0};
struct vfs_path vfs_root_path = {0};

static struct vfs_dcache_bucket {
    spinlock_t lock;
    struct hlist_node *head;
} vfs_dcache[VFS_DCACHE_BUCKETS];

static struct llist_header vfs_filesystems;
static mutex_t vfs_filesystems_lock;
static mutex_t vfs_mount_lock;
static mutex_t vfs_rename_lock;
static volatile unsigned int vfs_next_mnt_id = 1;
static volatile unsigned int vfs_next_peer_group_id = 1;
static volatile uint64_t vfs_mount_seq = 1;
static volatile uint64_t vfs_rename_seq = 1;

static struct vfs_mount *vfs_active_namespace_root_mount(void) {
    struct vfs_mount *mnt = task_mount_namespace_root(current_task);

    if (mnt)
        return mnt;
    if (vfs_init_mnt_ns.root)
        return vfs_init_mnt_ns.root;
    return vfs_root_path.mnt;
}

static struct vfs_mount *vfs_child_mount_at(struct vfs_mount *parent,
                                            struct vfs_dentry *mountpoint) {
    struct vfs_mount *mnt;

    if (!parent || !mountpoint)
        return NULL;

    for (mnt = mountpoint->d_mounted; mnt; mnt = mnt->mnt_stack_prev) {
        if (mnt->mnt_parent == parent)
            return mnt;
    }
    return NULL;
}

static void vfs_rebind_task_root_paths(const struct vfs_path *old_root,
                                       struct vfs_mount *new_mnt) {
    struct vfs_process_fs *fs;
    bool replace_root;
    bool replace_pwd;

    if (!old_root || !old_root->mnt || !old_root->dentry || !new_mnt ||
        !new_mnt->mnt_root) {
        return;
    }

    fs = task_current_vfs_fs();
    if (!fs)
        return;

    replace_root =
        fs->root.mnt == old_root->mnt && fs->root.dentry == old_root->dentry;
    replace_pwd =
        fs->pwd.mnt == old_root->mnt && fs->pwd.dentry == old_root->dentry;
    if (!replace_root && !replace_pwd)
        return;

    spin_lock(&fs->lock);
    if (replace_root) {
        vfs_path_put(&fs->root);
        fs->root.mnt = vfs_mntget(new_mnt);
        fs->root.dentry = vfs_dget(new_mnt->mnt_root);
    }
    if (replace_pwd) {
        vfs_path_put(&fs->pwd);
        fs->pwd.mnt = vfs_mntget(new_mnt);
        fs->pwd.dentry = vfs_dget(new_mnt->mnt_root);
    }
    fs->seq++;
    spin_unlock(&fs->lock);
}

static void vfs_rebind_namespace_root(const struct vfs_path *old_root,
                                      struct vfs_mount *new_mnt) {
    struct vfs_mount *active_root;

    if (!old_root || !old_root->mnt || !old_root->dentry || !new_mnt)
        return;

    active_root = vfs_active_namespace_root_mount();
    if (active_root != old_root->mnt ||
        old_root->dentry != old_root->mnt->mnt_root)
        return;

    (void)task_mount_namespace_set_root(current_task, new_mnt);

    if (vfs_root_path.mnt == old_root->mnt &&
        vfs_root_path.dentry == old_root->dentry) {
        vfs_path_put(&vfs_root_path);
        vfs_root_path.mnt = vfs_mntget(new_mnt);
        vfs_root_path.dentry = vfs_dget(new_mnt->mnt_root);
    }

    if (vfs_init_mnt_ns.root == old_root->mnt) {
        vfs_mntput(vfs_init_mnt_ns.root);
        vfs_init_mnt_ns.root = vfs_mntget(new_mnt);
        vfs_init_mnt_ns.seq++;
    }
}

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

static unsigned int vfs_alloc_peer_group_id(void) {
    return __atomic_add_fetch(&vfs_next_peer_group_id, 1, __ATOMIC_ACQ_REL);
}

static void
vfs_mount_apply_propagation(struct vfs_mount *mnt,
                            enum vfs_mount_propagation propagation) {
    if (!mnt)
        return;

    mnt->mnt_propagation = (uint8_t)propagation;
    switch (propagation) {
    case VFS_MNT_PROP_SHARED:
        if (!mnt->mnt_group_id)
            mnt->mnt_group_id = vfs_alloc_peer_group_id();
        mnt->mnt_master = NULL;
        break;
    case VFS_MNT_PROP_SLAVE:
        mnt->mnt_group_id = 0;
        if (mnt->mnt_parent && mnt->mnt_parent != mnt) {
            if (mnt->mnt_parent->mnt_propagation == VFS_MNT_PROP_SHARED)
                mnt->mnt_master = mnt->mnt_parent;
            else
                mnt->mnt_master = mnt->mnt_parent->mnt_master;
        } else {
            mnt->mnt_master = NULL;
        }
        break;
    case VFS_MNT_PROP_UNBINDABLE:
    case VFS_MNT_PROP_PRIVATE:
    default:
        mnt->mnt_group_id = 0;
        mnt->mnt_master = NULL;
        break;
    }
}

static void vfs_mount_apply_propagation_tree(struct vfs_mount *mnt,
                                             enum vfs_mount_propagation prop) {
    struct vfs_mount *child, *tmp;

    if (!mnt)
        return;

    vfs_mount_apply_propagation(mnt, prop);
    llist_for_each(child, tmp, &mnt->mnt_mounts, mnt_child) {
        vfs_mount_apply_propagation_tree(child, prop);
    }
}

static void vfs_sync_inode_compat(struct vfs_inode *inode) {
    if (!inode)
        return;

    inode->inode = inode->i_ino;
    inode->type = vfs_mode_to_type(inode->i_mode);
}

static uint32_t vfs_qstr_hash_bytes(const char *name, uint32_t len) {
    uint32_t hash = 2166136261u;
    uint32_t i = 0;

    while (name && i < len) {
        hash ^= (uint8_t)name[i++];
        hash *= 16777619u;
    }

    return hash ? hash : 1;
}

static inline bool vfs_qstr_equal(const struct vfs_qstr *a,
                                  const struct vfs_qstr *b) {
    if (!a || !b)
        return false;
    if (a->len != b->len || a->hash != b->hash)
        return false;
    if (!a->name || !b->name)
        return false;
    return strncmp(a->name, b->name, a->len) == 0;
}

static inline struct vfs_dcache_bucket *
vfs_dcache_bucket_for(struct vfs_super_block *sb, struct vfs_dentry *parent,
                      const struct vfs_qstr *name) {
    uintptr_t seed =
        ((uintptr_t)sb >> 6) ^ ((uintptr_t)parent >> 4) ^ name->hash;
    return &vfs_dcache[seed & (VFS_DCACHE_BUCKETS - 1)];
}

static void vfs_dentry_rehash(struct vfs_dentry *dentry) {
    struct vfs_dcache_bucket *bucket;

    if (!dentry || !dentry->d_parent || !dentry->d_sb)
        return;
    if (dentry->d_flags & VFS_DENTRY_HASHED)
        return;

    vfs_dget(dentry);
    bucket =
        vfs_dcache_bucket_for(dentry->d_sb, dentry->d_parent, &dentry->d_name);
    spin_lock(&bucket->lock);
    hlist_add(&bucket->head, &dentry->d_hash);
    dentry->d_flags |= VFS_DENTRY_HASHED;
    spin_unlock(&bucket->lock);
}

static void vfs_dentry_unhash(struct vfs_dentry *dentry) {
    struct vfs_dcache_bucket *bucket;
    bool had_cache_ref = false;

    if (!dentry || !(dentry->d_flags & VFS_DENTRY_HASHED))
        return;
    bucket =
        vfs_dcache_bucket_for(dentry->d_sb, dentry->d_parent, &dentry->d_name);
    spin_lock(&bucket->lock);
    if (dentry->d_flags & VFS_DENTRY_HASHED) {
        hlist_delete(&dentry->d_hash);
        dentry->d_flags &= ~VFS_DENTRY_HASHED;
        had_cache_ref = true;
    }
    spin_unlock(&bucket->lock);
    if (had_cache_ref)
        vfs_dput(dentry);
}

static inline bool vfs_is_root_dentry(const struct vfs_dentry *dentry) {
    return dentry &&
           ((dentry->d_flags & VFS_DENTRY_ROOT) || dentry->d_parent == dentry);
}

static inline bool vfs_path_is_absolute(const char *name) {
    return name && name[0] == '/';
}

static inline bool vfs_has_remaining_components(const char *rest) {
    if (!rest)
        return false;
    while (*rest) {
        if (*rest != '/')
            return true;
        rest++;
    }
    return false;
}

static void vfs_path_replace(struct vfs_path *dst, struct vfs_mount *mnt,
                             struct vfs_dentry *dentry) {
    if (!dst)
        return;
    vfs_path_put(dst);
    dst->mnt = vfs_mntget(mnt);
    dst->dentry = vfs_dget(dentry);
}

static int vfs_get_fs_start(int dfd, const char *name, struct vfs_path *start,
                            struct vfs_path *root) {
    struct vfs_process_fs *fs;
    struct vfs_file *file;

    if (!start || !root)
        return -EINVAL;
    memset(start, 0, sizeof(*start));
    memset(root, 0, sizeof(*root));

    fs = task_current_vfs_fs();
    if (!fs) {
        if (!vfs_root_path.mnt || !vfs_root_path.dentry)
            return -ENOENT;
        vfs_path_get(&vfs_root_path);
        *root = vfs_root_path;
        if (vfs_path_is_absolute(name) || dfd == AT_FDCWD) {
            vfs_path_get(&vfs_root_path);
            *start = vfs_root_path;
            return 0;
        }
        vfs_path_put(root);
        return -EBADF;
    }

    vfs_path_get(&fs->root);
    *root = fs->root;

    if (vfs_path_is_absolute(name)) {
        vfs_path_get(root);
        *start = *root;
        return 0;
    }

    if (dfd == AT_FDCWD) {
        vfs_path_get(&fs->pwd);
        *start = fs->pwd;
        return 0;
    }

    file = task_get_file(current_task, dfd);
    if (!file)
        goto err;

    vfs_path_get(&file->f_path);
    *start = file->f_path;
    vfs_file_put(file);
    return 0;

err:
    vfs_path_put(root);
    return -EBADF;
}

static struct vfs_dentry *vfs_lookup_component(struct vfs_path *parent,
                                               const char *component,
                                               unsigned int flags) {
    struct vfs_qstr qstr;
    struct vfs_dentry *dentry;
    struct vfs_inode *dir;

    if (!parent || !parent->dentry || !component || !component[0])
        return ERR_PTR(-ENOENT);

    vfs_qstr_make(&qstr, component);
    dentry = vfs_d_lookup(parent->dentry, &qstr);
    if (dentry) {
        if (dentry->d_op && dentry->d_op->d_revalidate) {
            int ret = dentry->d_op->d_revalidate(dentry, flags);
            if (ret < 0) {
                vfs_dput(dentry);
                return ERR_PTR(ret);
            }
            if (ret == 0) {
                vfs_dentry_unhash(dentry);
                vfs_dput(dentry);
                dentry = NULL;
            }
        }
        if (dentry)
            return dentry;
    }

    dir = parent->dentry->d_inode;
    if (!dir || !dir->i_op || !dir->i_op->lookup)
        return ERR_PTR(-ENOENT);

    dentry = vfs_d_alloc(parent->dentry->d_sb, parent->dentry, &qstr);
    if (!dentry)
        return ERR_PTR(-ENOMEM);

    {
        struct vfs_dentry *lookup = dir->i_op->lookup(dir, dentry, flags);
        if (IS_ERR(lookup)) {
            vfs_dput(dentry);
            return lookup;
        }
        if (!lookup) {
            vfs_dput(dentry);
            return ERR_PTR(-ENOENT);
        }
        if (lookup != dentry)
            vfs_dput(dentry);
        dentry = lookup;
    }
    if (!(dentry->d_flags & VFS_DENTRY_HASHED))
        vfs_d_add(parent->dentry, dentry);
    return dentry;
}

static void vfs_follow_mount(struct vfs_path *path) {
    while (path && path->dentry) {
        struct vfs_mount *mounted = vfs_child_mount_at(path->mnt, path->dentry);
        if (!mounted || !mounted->mnt_root)
            break;
        vfs_path_replace(path, mounted, mounted->mnt_root);
    }
}

static void vfs_follow_dotdot(struct vfs_path *path,
                              const struct vfs_path *root) {
    if (!path || !path->dentry || !path->mnt)
        return;

    while (path->dentry == path->mnt->mnt_root && path->mnt != root->mnt &&
           path->mnt->mnt_parent && path->mnt->mnt_mountpoint) {
        struct vfs_mount *parent_mnt = path->mnt->mnt_parent;
        struct vfs_dentry *mountpoint = path->mnt->mnt_mountpoint;
        vfs_path_replace(path, parent_mnt, mountpoint);
    }

    if (vfs_path_equal(path, root))
        return;
    if (path->dentry->d_parent)
        vfs_path_replace(path, path->mnt, path->dentry->d_parent);
}

static int __vfs_filename_lookup(struct vfs_path *start,
                                 const struct vfs_path *root, const char *name,
                                 unsigned int lookup_flags, unsigned int depth,
                                 struct vfs_path *out);

static int vfs_follow_symlink(struct vfs_path *parent,
                              const struct vfs_path *root,
                              struct vfs_dentry *link_dentry,
                              const char *remaining, unsigned int lookup_flags,
                              unsigned int depth, struct vfs_path *out) {
    const char *target;
    char *pathbuf;
    size_t target_len, rest_len;
    int ret;
    struct vfs_path next;

    if (depth >= VFS_MAX_SYMLINKS)
        return -ELOOP;
    if (!link_dentry || !link_dentry->d_inode || !link_dentry->d_inode->i_op ||
        !link_dentry->d_inode->i_op->get_link) {
        return -ELOOP;
    }

    target = link_dentry->d_inode->i_op->get_link(link_dentry,
                                                  link_dentry->d_inode, NULL);
    if (IS_ERR_OR_NULL(target))
        return target ? (int)PTR_ERR(target) : -ENOENT;

    target_len = strlen(target);
    rest_len = remaining ? strlen(remaining) : 0;
    pathbuf = malloc(target_len + (rest_len ? 1 + rest_len : 0) + 1);
    if (!pathbuf)
        return -ENOMEM;

    memcpy(pathbuf, target, target_len);
    if (rest_len) {
        pathbuf[target_len] = '/';
        memcpy(pathbuf + target_len + 1, remaining, rest_len);
        pathbuf[target_len + 1 + rest_len] = '\0';
    } else {
        pathbuf[target_len] = '\0';
    }

    memset(&next, 0, sizeof(next));
    if (target[0] == '/') {
        vfs_path_get((struct vfs_path *)root);
        next = *root;
    } else {
        vfs_path_get(parent);
        next = *parent;
    }

    ret = __vfs_filename_lookup(&next, root, pathbuf, lookup_flags, depth + 1,
                                out);
    vfs_path_put(&next);
    free(pathbuf);
    return ret;
}

static int __vfs_filename_lookup(struct vfs_path *start,
                                 const struct vfs_path *root, const char *name,
                                 unsigned int lookup_flags, unsigned int depth,
                                 struct vfs_path *out) {
    struct vfs_path path;
    char *walk;
    char *cursor;
    char *component;
    int ret = 0;

    if (!start || !root || !name || !out)
        return -EINVAL;

    if (lookup_flags & LOOKUP_EMPTY) {
        if (!name[0]) {
            vfs_path_get(start);
            *out = *start;
            return 0;
        }
    } else if (!name[0]) {
        return -ENOENT;
    }

    memset(&path, 0, sizeof(path));
    vfs_path_get(start);
    path = *start;

    walk = strdup(vfs_path_is_absolute(name) ? name + 1 : name);
    if (!walk) {
        vfs_path_put(&path);
        return -ENOMEM;
    }

    if (!walk[0]) {
        *out = path;
        free(walk);
        return 0;
    }

    cursor = walk;
    while ((component = pathtok(&cursor))) {
        struct vfs_dentry *next;
        bool has_remaining;

        if (streq(component, "."))
            continue;

        if (streq(component, "..")) {
            vfs_follow_dotdot(&path, root);
            continue;
        }

        if (!path.dentry || !path.dentry->d_inode) {
            ret = -ENOENT;
            goto out;
        }
        if (!S_ISDIR(path.dentry->d_inode->i_mode)) {
            ret = -ENOTDIR;
            goto out;
        }

        next = vfs_lookup_component(&path, component, lookup_flags);
        if (IS_ERR(next)) {
            ret = (int)PTR_ERR(next);
            goto out;
        }
        if (!next->d_inode) {
            vfs_dput(next);
            ret = -ENOENT;
            goto out;
        }

        has_remaining = vfs_has_remaining_components(cursor);
        if (S_ISLNK(next->d_inode->i_mode) &&
            (!(lookup_flags & LOOKUP_NOFOLLOW) || has_remaining ||
             (lookup_flags & LOOKUP_FOLLOW))) {
            ret = vfs_follow_symlink(&path, root, next, cursor, lookup_flags,
                                     depth, out);
            vfs_dput(next);
            goto out_no_path_put;
        }

        vfs_path_replace(&path, path.mnt, next);
        vfs_dput(next);
        if (!(lookup_flags & LOOKUP_NO_LAST_MOUNT) || has_remaining)
            vfs_follow_mount(&path);
    }

    if ((lookup_flags & LOOKUP_DIRECTORY) && path.dentry &&
        path.dentry->d_inode && !S_ISDIR(path.dentry->d_inode->i_mode)) {
        ret = -ENOTDIR;
        goto out;
    }

    *out = path;
    free(walk);
    return 0;

out:
    vfs_path_put(&path);
out_no_path_put:
    free(walk);
    return ret;
}

static int vfs_open_last_lookups(int dfd, const char *name,
                                 const struct vfs_open_how *how,
                                 struct vfs_path *parent, struct vfs_qstr *last,
                                 struct vfs_dentry **res_dentry) {
    struct vfs_dentry *dentry;
    unsigned int parent_type = 0;
    int ret;

    ret = vfs_path_parent_lookup(dfd, name, LOOKUP_PARENT, parent, last,
                                 &parent_type);
    if (ret < 0)
        return ret;
    if (!parent->dentry || !parent->dentry->d_inode)
        return -ENOENT;
    if (!S_ISDIR(parent->dentry->d_inode->i_mode))
        return -ENOTDIR;

    dentry = vfs_d_lookup(parent->dentry, last);
    if (!dentry) {
        if (parent->dentry->d_inode->i_op &&
            parent->dentry->d_inode->i_op->lookup) {
            dentry = vfs_d_alloc(parent->dentry->d_sb, parent->dentry, last);
            if (!dentry)
                return -ENOMEM;
            {
                struct vfs_dentry *lookup =
                    parent->dentry->d_inode->i_op->lookup(
                        parent->dentry->d_inode, dentry, LOOKUP_CREATE);
                if (IS_ERR(lookup)) {
                    vfs_dput(dentry);
                    return (int)PTR_ERR(lookup);
                }
                if (!lookup) {
                    vfs_dput(dentry);
                    dentry = NULL;
                } else {
                    if (lookup != dentry)
                        vfs_dput(dentry);
                    dentry = lookup;
                }
            }
            if (dentry && !(dentry->d_flags & VFS_DENTRY_HASHED))
                vfs_d_add(parent->dentry, dentry);
        }
    }

    if (!dentry && !(how->flags & O_CREAT))
        return -ENOENT;
    *res_dentry = dentry;
    return 0;
}

void vfs_qstr_make(struct vfs_qstr *qstr, const char *name) {
    if (!qstr)
        return;
    memset(qstr, 0, sizeof(*qstr));
    if (!name)
        return;
    qstr->name = name;
    qstr->len = (uint32_t)strlen(name);
    qstr->hash = vfs_qstr_hash_bytes(name, qstr->len);
}

void vfs_qstr_dup(struct vfs_qstr *qstr, const char *name) {
    if (!qstr)
        return;
    memset(qstr, 0, sizeof(*qstr));
    if (!name)
        return;
    qstr->name = strdup(name);
    if (!qstr->name)
        return;
    qstr->len = (uint32_t)strlen(qstr->name);
    qstr->hash = vfs_qstr_hash_bytes(qstr->name, qstr->len);
}

void vfs_qstr_destroy(struct vfs_qstr *qstr) {
    if (!qstr)
        return;
    if (qstr->name)
        free((void *)qstr->name);
    memset(qstr, 0, sizeof(*qstr));
}

int vfs_init(void) {
    unsigned int i;

    llist_init_head(&vfs_filesystems);
    mutex_init(&vfs_filesystems_lock);
    mutex_init(&vfs_mount_lock);
    mutex_init(&vfs_rename_lock);
    mutex_init(&vfs_init_mnt_ns.lock);

    for (i = 0; i < VFS_DCACHE_BUCKETS; ++i) {
        spin_init(&vfs_dcache[i].lock);
        vfs_dcache[i].head = NULL;
    }

    memset(&vfs_root_path, 0, sizeof(vfs_root_path));
    return 0;
}

int vfs_register_filesystem(struct vfs_file_system_type *fs) {
    struct vfs_file_system_type *pos, *tmp;

    if (!fs || !fs->name || !fs->get_tree)
        return -EINVAL;
    if (!fs->fs_list.next && !fs->fs_list.prev)
        llist_init_head(&fs->fs_list);

    mutex_lock(&vfs_filesystems_lock);
    llist_for_each(pos, tmp, &vfs_filesystems, fs_list) {
        if (streq(pos->name, fs->name)) {
            mutex_unlock(&vfs_filesystems_lock);
            return -EEXIST;
        }
    }
    if (llist_empty(&fs->fs_list))
        llist_append(&vfs_filesystems, &fs->fs_list);
    mutex_unlock(&vfs_filesystems_lock);
    return 0;
}

void vfs_unregister_filesystem(struct vfs_file_system_type *fs) {
    if (!fs)
        return;
    if (!fs->fs_list.next || !fs->fs_list.prev)
        return;
    mutex_lock(&vfs_filesystems_lock);
    if (!llist_empty(&fs->fs_list))
        llist_delete(&fs->fs_list);
    mutex_unlock(&vfs_filesystems_lock);
}

struct vfs_file_system_type *vfs_get_fs_type(const char *name) {
    struct vfs_file_system_type *pos, *tmp;

    if (!name)
        return NULL;
    mutex_lock(&vfs_filesystems_lock);
    llist_for_each(pos, tmp, &vfs_filesystems, fs_list) {
        if (streq(pos->name, name)) {
            mutex_unlock(&vfs_filesystems_lock);
            return pos;
        }
    }
    mutex_unlock(&vfs_filesystems_lock);
    return NULL;
}

struct vfs_super_block *vfs_alloc_super(struct vfs_file_system_type *type,
                                        unsigned long sb_flags) {
    struct vfs_super_block *sb = malloc(sizeof(*sb));
    if (!sb)
        return NULL;

    memset(sb, 0, sizeof(*sb));
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

void vfs_get_super(struct vfs_super_block *sb) {
    if (!sb)
        return;
    vfs_ref_get(&sb->s_ref);
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
    inode->flock_lock.l_pid = 0;
    inode->flock_lock.l_type = F_UNLCK;
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

struct vfs_dentry *vfs_d_alloc(struct vfs_super_block *sb,
                               struct vfs_dentry *parent,
                               const struct vfs_qstr *name) {
    struct vfs_dentry *dentry = malloc(sizeof(*dentry));
    if (!dentry)
        return NULL;

    memset(dentry, 0, sizeof(*dentry));
    spin_init(&dentry->d_lock);
    spin_init(&dentry->d_children_lock);
    vfs_lockref_init(&dentry->d_lockref, 1);
    llist_init_head(&dentry->d_child);
    llist_init_head(&dentry->d_subdirs);
    llist_init_head(&dentry->d_alias);
    dentry->d_sb = sb;
    dentry->d_parent = parent ? vfs_dget(parent) : dentry;
    dentry->d_op = sb ? sb->s_d_op : NULL;

    if (name && name->name) {
        dentry->d_name.name = strdup(name->name);
        dentry->d_name.len = name->len;
        dentry->d_name.hash = name->hash;
        if (!dentry->d_name.name) {
            free(dentry);
            return NULL;
        }
    } else {
        dentry->d_name.name = strdup("");
        dentry->d_name.len = 0;
        dentry->d_name.hash = 0;
    }

    if (!parent)
        dentry->d_flags |= VFS_DENTRY_ROOT;
    return dentry;
}

struct vfs_dentry *vfs_dget(struct vfs_dentry *dentry) {
    if (!dentry)
        return NULL;
    vfs_lockref_get(&dentry->d_lockref);
    return dentry;
}

void vfs_dput(struct vfs_dentry *dentry) {
    struct vfs_dentry *parent;

    if (!dentry)
        return;
    if (!vfs_lockref_put(&dentry->d_lockref))
        return;

    if (dentry->d_op && dentry->d_op->d_release)
        dentry->d_op->d_release(dentry);

    if (dentry->d_parent && dentry->d_parent != dentry &&
        !llist_empty(&dentry->d_child)) {
        spin_lock(&dentry->d_parent->d_children_lock);
        if (!llist_empty(&dentry->d_child))
            llist_delete(&dentry->d_child);
        spin_unlock(&dentry->d_parent->d_children_lock);
    }

    if (dentry->d_flags & VFS_DENTRY_HASHED)
        vfs_dentry_unhash(dentry);

    if (dentry->d_inode)
        vfs_iput(dentry->d_inode);

    parent = dentry->d_parent;
    if (dentry->d_name.name)
        free((void *)dentry->d_name.name);
    free(dentry);

    if (parent && parent != dentry)
        vfs_dput(parent);
}

void vfs_d_add(struct vfs_dentry *parent, struct vfs_dentry *dentry) {
    if (!dentry)
        return;

    if (!dentry->d_parent && parent)
        dentry->d_parent = vfs_dget(parent);

    if (parent && llist_empty(&dentry->d_child)) {
        spin_lock(&parent->d_children_lock);
        if (llist_empty(&dentry->d_child))
            llist_append(&parent->d_subdirs, &dentry->d_child);
        spin_unlock(&parent->d_children_lock);
    }

    vfs_dentry_rehash(dentry);
}

void vfs_d_instantiate(struct vfs_dentry *dentry, struct vfs_inode *inode) {
    if (!dentry)
        return;
    if (dentry->d_inode)
        vfs_iput(dentry->d_inode);

    dentry->d_inode = vfs_igrab(inode);
    if (inode) {
        vfs_sync_inode_compat(inode);
        dentry->d_flags &= ~VFS_DENTRY_NEGATIVE;
        if (llist_empty(&dentry->d_alias))
            llist_append(&inode->i_dentry_aliases, &dentry->d_alias);
    } else {
        dentry->d_flags |= VFS_DENTRY_NEGATIVE;
    }
    dentry->d_seq++;
}

struct vfs_dentry *vfs_d_lookup(struct vfs_dentry *parent,
                                const struct vfs_qstr *name) {
    struct vfs_dcache_bucket *bucket;
    struct hlist_node *node;

    if (!parent || !name)
        return NULL;

    bucket = vfs_dcache_bucket_for(parent->d_sb, parent, name);
    spin_lock(&bucket->lock);
    for (node = bucket->head; node; node = node->next) {
        struct vfs_dentry *dentry =
            container_of(node, struct vfs_dentry, d_hash);
        if (dentry->d_parent != parent)
            continue;
        if (!vfs_qstr_equal(&dentry->d_name, name))
            continue;
        vfs_dget(dentry);
        spin_unlock(&bucket->lock);
        return dentry;
    }
    spin_unlock(&bucket->lock);
    return NULL;
}

struct vfs_mount *vfs_mount_alloc(struct vfs_super_block *sb,
                                  unsigned long mnt_flags) {
    struct vfs_mount *mnt;

    if (!sb || !sb->s_root)
        return NULL;

    mnt = malloc(sizeof(*mnt));
    if (!mnt)
        return NULL;

    memset(mnt, 0, sizeof(*mnt));
    mnt->mnt_parent = mnt;
    mnt->mnt_root = vfs_dget(sb->s_root);
    mnt->mnt_sb = sb;
    mnt->mnt_flags = mnt_flags;
    mnt->mnt_propagation = VFS_MNT_PROP_PRIVATE;
    mnt->mnt_id = __atomic_add_fetch(&vfs_next_mnt_id, 1, __ATOMIC_ACQ_REL);
    vfs_ref_init(&mnt->mnt_ref, 1);
    spin_init(&mnt->mnt_lock);
    llist_init_head(&mnt->mnt_sb_link);
    llist_init_head(&mnt->mnt_child);
    llist_init_head(&mnt->mnt_mounts);

    vfs_get_super(sb);
    spin_lock(&sb->s_mount_lock);
    llist_append(&sb->s_mounts, &mnt->mnt_sb_link);
    spin_unlock(&sb->s_mount_lock);

    return mnt;
}

struct vfs_mount *vfs_mntget(struct vfs_mount *mnt) {
    if (!mnt)
        return NULL;
    vfs_ref_get(&mnt->mnt_ref);
    return mnt;
}

void vfs_mntput(struct vfs_mount *mnt) {
    if (!mnt)
        return;
    if (!vfs_ref_put(&mnt->mnt_ref))
        return;
    if (!llist_empty(&mnt->mnt_child))
        llist_delete(&mnt->mnt_child);
    if (!llist_empty(&mnt->mnt_sb_link))
        llist_delete(&mnt->mnt_sb_link);
    if (mnt->mnt_mountpoint)
        vfs_dput(mnt->mnt_mountpoint);
    if (mnt->mnt_root)
        vfs_dput(mnt->mnt_root);
    if (mnt->mnt_sb)
        vfs_put_super(mnt->mnt_sb);
    free(mnt);
}

int vfs_mount_attach(struct vfs_mount *parent, struct vfs_dentry *mountpoint,
                     struct vfs_mount *child) {
    if (!mountpoint || !child)
        return -EINVAL;

    mutex_lock(&vfs_mount_lock);
    if (child->mnt_mountpoint || child->mnt_stack_prev ||
        child->mnt_stack_next || !llist_empty(&child->mnt_child)) {
        mutex_unlock(&vfs_mount_lock);
        return -EBUSY;
    }

    child->mnt_parent = parent ? parent : child;
    child->mnt_mountpoint = vfs_dget(mountpoint);
    child->mnt_stack_prev = mountpoint->d_mounted;
    child->mnt_stack_next = NULL;
    if (child->mnt_stack_prev)
        child->mnt_stack_prev->mnt_stack_next = child;
    mountpoint->d_mounted = child;
    mountpoint->d_flags |= VFS_DENTRY_MOUNTPOINT;
    if (parent)
        llist_append(&parent->mnt_mounts, &child->mnt_child);

    if (parent) {
        switch (parent->mnt_propagation) {
        case VFS_MNT_PROP_SHARED:
            vfs_mount_apply_propagation(child, VFS_MNT_PROP_SHARED);
            break;
        case VFS_MNT_PROP_SLAVE:
            vfs_mount_apply_propagation(child, VFS_MNT_PROP_SLAVE);
            break;
        case VFS_MNT_PROP_UNBINDABLE:
            vfs_mount_apply_propagation(child, VFS_MNT_PROP_UNBINDABLE);
            break;
        case VFS_MNT_PROP_PRIVATE:
        default:
            vfs_mount_apply_propagation(child, VFS_MNT_PROP_PRIVATE);
            break;
        }
    }

    __atomic_add_fetch(&vfs_mount_seq, 1, __ATOMIC_ACQ_REL);
    vfs_init_mnt_ns.seq++;
    if (!vfs_init_mnt_ns.root)
        vfs_init_mnt_ns.root = child;
    mutex_unlock(&vfs_mount_lock);
    return 0;
}

void vfs_mount_detach(struct vfs_mount *mnt) {
    struct vfs_dentry *mountpoint;
    struct vfs_mount *below;
    struct vfs_mount *above;

    if (!mnt)
        return;

    mutex_lock(&vfs_mount_lock);
    mountpoint = mnt->mnt_mountpoint;
    below = mnt->mnt_stack_prev;
    above = mnt->mnt_stack_next;

    if (above)
        above->mnt_stack_prev = below;
    if (below)
        below->mnt_stack_next = above;

    if (mountpoint && mountpoint->d_mounted == mnt)
        mountpoint->d_mounted = below;
    if (mountpoint && !mountpoint->d_mounted)
        mountpoint->d_flags &= ~VFS_DENTRY_MOUNTPOINT;

    mnt->mnt_parent = mnt;
    mnt->mnt_mountpoint = NULL;
    mnt->mnt_stack_prev = NULL;
    mnt->mnt_stack_next = NULL;

    if (!llist_empty(&mnt->mnt_child))
        llist_delete(&mnt->mnt_child);

    __atomic_add_fetch(&vfs_mount_seq, 1, __ATOMIC_ACQ_REL);
    vfs_init_mnt_ns.seq++;
    mutex_unlock(&vfs_mount_lock);

    if (mountpoint)
        vfs_dput(mountpoint);
}

struct vfs_mount *vfs_path_mount(const struct vfs_path *path) {
    struct vfs_mount *root_mnt;
    struct vfs_mount *mnt;

    if (!path)
        return NULL;

    root_mnt = vfs_active_namespace_root_mount();
    mnt = (path->mnt && path->dentry)
              ? vfs_child_mount_at(path->mnt, path->dentry)
              : NULL;
    if (mnt)
        return vfs_mntget(mnt);

    if (path->mnt && path->mnt != root_mnt)
        return vfs_mntget(path->mnt);
    return NULL;
}

static struct vfs_mount *vfs_clone_single_mount(struct vfs_mount *src) {
    struct vfs_mount *dst;

    if (!src)
        return NULL;

    dst = vfs_mount_alloc(src->mnt_sb, src->mnt_flags);
    if (!dst)
        return NULL;

    vfs_mount_apply_propagation(dst, src->mnt_propagation);
    return dst;
}

static int vfs_clone_mount_children(struct vfs_mount *src_parent,
                                    struct vfs_mount *dst_parent) {
    struct vfs_mount *src_child, *tmp;

    llist_for_each(src_child, tmp, &src_parent->mnt_mounts, mnt_child) {
        struct vfs_mount *dst_child = vfs_clone_single_mount(src_child);
        int ret;

        if (!dst_child)
            return -ENOMEM;

        ret =
            vfs_mount_attach(dst_parent, src_child->mnt_mountpoint, dst_child);
        if (ret < 0) {
            vfs_mntput(dst_child);
            return ret;
        }

        ret = vfs_clone_mount_children(src_child, dst_child);
        if (ret < 0)
            return ret;
    }

    return 0;
}

struct vfs_mount *vfs_clone_mount_tree(struct vfs_mount *root) {
    struct vfs_mount *clone;
    int ret;

    if (!root)
        return NULL;

    clone = vfs_clone_single_mount(root);
    if (!clone)
        return NULL;

    clone->mnt_parent = clone;
    clone->mnt_mountpoint = NULL;
    clone->mnt_stack_prev = NULL;
    clone->mnt_stack_next = NULL;

    ret = vfs_clone_mount_children(root, clone);
    if (ret < 0) {
        vfs_put_mount_tree(clone);
        return NULL;
    }

    return clone;
}

void vfs_put_mount_tree(struct vfs_mount *root) {
    struct vfs_mount *child, *tmp;

    if (!root)
        return;

    llist_for_each(child, tmp, &root->mnt_mounts, mnt_child) {
        vfs_put_mount_tree(child);
    }

    if (root->mnt_mountpoint)
        vfs_mount_detach(root);
    vfs_mntput(root);
}

int vfs_reconfigure_mount(struct vfs_mount *mnt, const struct vfs_path *to_path,
                          bool detached) {
    struct vfs_mount *old_parent = NULL;
    struct vfs_dentry *old_mountpoint = NULL;
    struct vfs_path old_root = {0};
    int ret;

    if (!mnt || !to_path || !to_path->mnt || !to_path->dentry ||
        !to_path->dentry->d_inode) {
        return -EINVAL;
    }

    if (!S_ISDIR(to_path->dentry->d_inode->i_mode))
        return -ENOTDIR;

    if (!detached && mnt->mnt_parent == to_path->mnt &&
        mnt->mnt_mountpoint == to_path->dentry &&
        to_path->dentry->d_mounted == mnt) {
        return 0;
    }

    old_root = *to_path;
    vfs_path_get(&old_root);

    if (!detached) {
        old_parent = mnt->mnt_parent != mnt ? mnt->mnt_parent : NULL;
        old_mountpoint =
            mnt->mnt_mountpoint ? vfs_dget(mnt->mnt_mountpoint) : NULL;
        vfs_mount_detach(mnt);
    }

    ret = vfs_mount_attach(to_path->mnt, to_path->dentry, mnt);
    if (ret < 0) {
        if (!detached && old_mountpoint)
            (void)vfs_mount_attach(old_parent, old_mountpoint, mnt);
        goto out;
    }

    vfs_rebind_task_root_paths(&old_root, mnt);
    vfs_rebind_namespace_root(&old_root, mnt);

out:
    if (old_mountpoint)
        vfs_dput(old_mountpoint);
    vfs_path_put(&old_root);
    return ret;
}

int vfs_mount_set_propagation(struct vfs_mount *mnt, unsigned long flags,
                              bool recursive) {
    enum vfs_mount_propagation propagation;

    if (!mnt)
        return -EINVAL;

    switch (flags) {
    case MS_SHARED:
        propagation = VFS_MNT_PROP_SHARED;
        break;
    case MS_PRIVATE:
        propagation = VFS_MNT_PROP_PRIVATE;
        break;
    case MS_SLAVE:
        propagation = VFS_MNT_PROP_SLAVE;
        break;
    case MS_UNBINDABLE:
        propagation = VFS_MNT_PROP_UNBINDABLE;
        break;
    default:
        return -EINVAL;
    }

    mutex_lock(&vfs_mount_lock);
    if (recursive)
        vfs_mount_apply_propagation_tree(mnt, propagation);
    else
        vfs_mount_apply_propagation(mnt, propagation);
    __atomic_add_fetch(&vfs_mount_seq, 1, __ATOMIC_ACQ_REL);
    vfs_init_mnt_ns.seq++;
    mutex_unlock(&vfs_mount_lock);
    return 0;
}

bool vfs_mount_is_shared(const struct vfs_mount *mnt) {
    return mnt && mnt->mnt_propagation == VFS_MNT_PROP_SHARED &&
           mnt->mnt_group_id != 0;
}

unsigned int vfs_mount_peer_group_id(const struct vfs_mount *mnt) {
    return mnt ? mnt->mnt_group_id : 0;
}

unsigned int vfs_mount_master_group_id(const struct vfs_mount *mnt) {
    if (!mnt || !mnt->mnt_master)
        return 0;
    return mnt->mnt_master->mnt_group_id;
}

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

struct vfs_file *vfs_alloc_file(const struct vfs_path *path,
                                unsigned int open_flags) {
    struct vfs_file *file;

    if (!path || !path->dentry || !path->dentry->d_inode)
        return NULL;

    file = malloc(sizeof(*file));
    if (!file)
        return NULL;

    memset(file, 0, sizeof(*file));
    vfs_path_get((struct vfs_path *)path);
    file->f_path = *path;
    file->f_inode = vfs_igrab(path->dentry->d_inode);
    file->node = file->f_inode;
    file->f_op = file->f_inode->i_fop;
    file->f_flags = open_flags;
    mutex_init(&file->f_pos_lock);
    spin_init(&file->f_lock);
    vfs_ref_init(&file->f_ref, 1);
    return file;
}

struct vfs_file *vfs_file_get(struct vfs_file *file) {
    if (!file)
        return NULL;
    vfs_ref_get(&file->f_ref);
    return file;
}

void vfs_file_put(struct vfs_file *file) {
    if (!file)
        return;
    if (!vfs_ref_put(&file->f_ref))
        return;

    if (file->f_op && file->f_op->release)
        file->f_op->release(file->f_inode, file);
    if (file->f_inode)
        vfs_iput(file->f_inode);
    vfs_path_put(&file->f_path);
    free(file);
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

void vfs_poll_wait_init(vfs_poll_wait_t *wait, struct task *task,
                        uint32_t events) {
    if (!wait)
        return;

    memset(wait, 0, sizeof(*wait));
    wait->task = task;
    wait->events = events;
    llist_init_head(&wait->node);
}

int vfs_poll_wait_arm(vfs_node_t *node, vfs_poll_wait_t *wait) {
    if (!node || !wait || !wait->task)
        return -EINVAL;
    if (wait->armed)
        return 0;

    wait->watch_node = node;
    wait->revents = 0;

    spin_lock(&node->poll_waiters_lock);
    llist_append(&node->poll_waiters, &wait->node);
    wait->armed = true;
    vfs_igrab(node);
    spin_unlock(&node->poll_waiters_lock);
    return 0;
}

void vfs_poll_wait_disarm(vfs_poll_wait_t *wait) {
    vfs_node_t *node;

    if (!wait || !wait->armed || !wait->watch_node)
        return;

    node = wait->watch_node;
    spin_lock(&node->poll_waiters_lock);
    if (wait->armed) {
        llist_delete(&wait->node);
        wait->armed = false;
        vfs_iput(node);
    }
    spin_unlock(&node->poll_waiters_lock);

    wait->watch_node = NULL;
    llist_init_head(&wait->node);
}

int vfs_poll_wait_sleep(vfs_node_t *node, vfs_poll_wait_t *wait,
                        int64_t timeout_ns, const char *reason) {
    uint32_t want;
    uint64_t deadline = UINT64_MAX;
    bool irq_state;

    if (!node || !wait || !wait->task)
        return -EINVAL;

    want = wait->events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    if (timeout_ns >= 0)
        deadline = nano_time() + (uint64_t)timeout_ns;

    while (true) {
        if (wait->revents & want)
            return EOK;
        if (task_signal_has_deliverable(wait->task))
            return -EINTR;
        if (timeout_ns == 0)
            return ETIMEDOUT;

        int64_t block_ns = -1;
        if (timeout_ns >= 0) {
            uint64_t now = nano_time();
            if (now >= deadline)
                return ETIMEDOUT;
            block_ns = (int64_t)(deadline - now);
        }
        if (block_ns < 0 || block_ns > 10000000LL)
            block_ns = 10000000LL;

        irq_state = arch_interrupt_enabled();
        arch_enable_interrupt();
        int ret = task_block(wait->task, TASK_BLOCKING, block_ns, reason);
        if (!irq_state)
            arch_disable_interrupt();
        if (ret == EOK || ret == ETIMEDOUT)
            continue;
        return ret;
    }
}

void vfs_poll_notify(vfs_node_t *node, uint32_t events) {
    vfs_poll_wait_t *pos, *tmp;

    if (!node || !events)
        return;

    spin_lock(&node->poll_waiters_lock);
    if (events & (EPOLLIN | EPOLLRDNORM | EPOLLRDBAND | EPOLLRDHUP))
        node->poll_seq_in++;
    if (events & (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND))
        node->poll_seq_out++;
    if (events & (EPOLLPRI | EPOLLMSG))
        node->poll_seq_pri++;

    llist_for_each(pos, tmp, &node->poll_waiters, node) {
        pos->revents |= events;
        if (pos->task)
            task_unblock(pos->task, EOK);
    }
    spin_unlock(&node->poll_waiters_lock);
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
            cursor.dentry == cursor.dentry->d_parent)
            break;

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
            cursor.dentry == cursor.dentry->d_parent)
            break;

        cursor.dentry = cursor.dentry->d_parent;
    }

    return false;
}

int vfs_filename_lookup(int dfd, const char *name, unsigned int lookup_flags,
                        struct vfs_path *path) {
    struct vfs_path start, root;
    int ret;

    if (!name || !path)
        return -EINVAL;

    memset(&start, 0, sizeof(start));
    memset(&root, 0, sizeof(root));
    ret = vfs_get_fs_start(dfd, name, &start, &root);
    if (ret < 0)
        return ret;

    ret = __vfs_filename_lookup(&start, &root, name, lookup_flags, 0, path);
    vfs_path_put(&start);
    vfs_path_put(&root);
    return ret;
}

int vfs_path_parent_lookup(int dfd, const char *name, unsigned int lookup_flags,
                           struct vfs_path *parent, struct vfs_qstr *last,
                           unsigned int *type) {
    char *copy, *basename, *slash;
    struct vfs_path root = {0};
    int ret;

    if (!name || !parent || !last)
        return -EINVAL;

    copy = strdup(name);
    if (!copy)
        return -ENOMEM;

    while (strlen(copy) > 1 && copy[strlen(copy) - 1] == '/')
        copy[strlen(copy) - 1] = '\0';

    slash = strrchr(copy, '/');
    if (!slash) {
        ret = vfs_get_fs_start(dfd, copy, parent, &root);
        if (ret < 0) {
            free(copy);
            return ret;
        }
        vfs_path_put(&root);
        vfs_qstr_dup(last, copy);
        if (type)
            *type = 0;
        free(copy);
        return 0;
    }

    if (slash == copy) {
        basename = slash + 1;
        while (*basename == '/')
            basename++;
        vfs_qstr_dup(last, basename[0] ? basename : ".");
        slash[1] = '\0';
    } else {
        basename = slash + 1;
        while (*basename == '/')
            basename++;
        vfs_qstr_dup(last, basename[0] ? basename : ".");
        *slash = '\0';
    }
    ret = vfs_filename_lookup(dfd, copy[0] ? copy : "/", lookup_flags, parent);
    if (type)
        *type = 0;
    free(copy);
    return ret;
}

int vfs_openat(int dfd, const char *name, const struct vfs_open_how *how,
               struct vfs_file **out) {
    struct vfs_open_how local_how;
    struct vfs_path parent = {0};
    struct vfs_path target = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *dentry = NULL;
    struct vfs_file *file;
    struct vfs_inode *dir;
    struct vfs_path *open_path;
    bool dentry_owned_by_target = false;
    bool created = false;
    int ret;

    if (!name || !out)
        return -EINVAL;

    memset(&local_how, 0, sizeof(local_how));
    if (how)
        local_how = *how;
    if ((local_how.flags & O_CREAT) && current_task && current_task->fs)
        local_how.mode &= ~current_task->fs->umask;

    ret = vfs_open_last_lookups(dfd, name, &local_how, &parent, &last, &dentry);
    if (ret < 0)
        goto out;

    dir = parent.dentry->d_inode;
    if (!dentry || !dentry->d_inode) {
        if (!(local_how.flags & O_CREAT)) {
            ret = -ENOENT;
            goto out;
        }
        dentry = vfs_d_alloc(parent.dentry->d_sb, parent.dentry, &last);
        if (!dentry) {
            ret = -ENOMEM;
            goto out;
        }
        if (!dir->i_op || !dir->i_op->create) {
            ret = -EOPNOTSUPP;
            goto out;
        }
        ret = dir->i_op->create(dir, dentry, (umode_t)local_how.mode,
                                !!(local_how.flags & O_EXCL));
        if (ret < 0)
            goto out;
        created = true;
        if (!(dentry->d_flags & VFS_DENTRY_HASHED))
            vfs_d_add(parent.dentry, dentry);
    } else if ((local_how.flags & O_CREAT) && (local_how.flags & O_EXCL)) {
        ret = -EEXIST;
        goto out;
    }

    if (!dentry->d_inode) {
        ret = -ENOENT;
        goto out;
    }

    open_path = &(struct vfs_path){.mnt = parent.mnt, .dentry = dentry};
    if (!created) {
        struct vfs_path mounted = {0};

        vfs_path_get(open_path);
        mounted = *open_path;
        vfs_follow_mount(&mounted);
        if (mounted.mnt != parent.mnt || mounted.dentry != dentry) {
            target = mounted;
            open_path = &target;
            dentry = target.dentry;
            dentry_owned_by_target = true;
        } else {
            vfs_path_put(&mounted);
        }
    }

    if (!created && S_ISLNK(dentry->d_inode->i_mode)) {
        if (local_how.flags & O_NOFOLLOW) {
            if (!(local_how.flags & O_PATH)) {
                ret = -ELOOP;
                goto out;
            }
        } else {
            ret = vfs_filename_lookup(dfd, name, LOOKUP_FOLLOW, &target);
            if (ret < 0)
                goto out;
            if (!target.dentry || !target.dentry->d_inode) {
                ret = -ENOENT;
                goto out;
            }
            open_path = &target;
            dentry = target.dentry;
            dentry_owned_by_target = true;
        }
    }

    if ((local_how.flags & O_DIRECTORY) && !S_ISDIR(dentry->d_inode->i_mode)) {
        ret = -ENOTDIR;
        goto out;
    }
    if ((local_how.flags & O_TRUNC) &&
        ((local_how.flags & O_ACCMODE_FLAGS) == O_WRONLY ||
         (local_how.flags & O_ACCMODE_FLAGS) == O_RDWR) &&
        !S_ISDIR(dentry->d_inode->i_mode)) {
        ret = vfs_truncate_path(open_path, 0);
        if (ret < 0)
            goto out;
    }

    file = vfs_alloc_file(open_path, (unsigned int)local_how.flags);
    if (!file) {
        ret = -ENOMEM;
        goto out;
    }

    if (dentry->d_inode->i_op && dentry->d_inode->i_op->atomic_open) {
        ret = dentry->d_inode->i_op->atomic_open(dir, dentry, file,
                                                 (unsigned int)local_how.flags,
                                                 (umode_t)local_how.mode);
        if (ret < 0) {
            vfs_file_put(file);
            goto out;
        }
    } else if (file->f_op && file->f_op->open) {
        ret = file->f_op->open(dentry->d_inode, file);
        if (ret < 0) {
            vfs_file_put(file);
            goto out;
        }
    }

    if (created)
        notifyfs_queue_inode_event(dir, dentry->d_inode, last.name, IN_CREATE,
                                   0);

    notifyfs_queue_inode_event(dentry->d_inode, dentry->d_inode, NULL, IN_OPEN,
                               0);
    *out = file;
    ret = 0;

out:
    vfs_path_put(&target);
    if (dentry && !dentry_owned_by_target)
        vfs_dput(dentry);
    vfs_path_put(&parent);
    vfs_qstr_destroy(&last);
    return ret;
}

int vfs_close_file(struct vfs_file *file) {
    uint64_t close_mask;

    if (!file)
        return -EBADF;
    if (file->f_op && file->f_op->flush)
        file->f_op->flush(file);
    close_mask = ((file->f_flags & O_ACCMODE_FLAGS) == O_RDONLY)
                     ? IN_CLOSE_NOWRITE
                     : IN_CLOSE_WRITE;
    notifyfs_queue_inode_event(file->f_inode, file->f_inode, NULL, close_mask,
                               0);
    vfs_file_put(file);
    return 0;
}

ssize_t vfs_read_file(struct vfs_file *file, void *buf, size_t count,
                      loff_t *ppos) {
    ssize_t ret;
    loff_t pos;

    if (!file || !file->f_op || !file->f_op->read)
        return -EINVAL;

    if (ppos) {
        pos = *ppos;
        ret = file->f_op->read(file, buf, count, &pos);
        if (ret >= 0)
            *ppos = pos;
        return ret;
    }

    mutex_lock(&file->f_pos_lock);
    pos = file->f_pos;
    ret = file->f_op->read(file, buf, count, &pos);
    if (ret >= 0)
        file->f_pos = pos;
    mutex_unlock(&file->f_pos_lock);
    return ret;
}

ssize_t vfs_write_file(struct vfs_file *file, const void *buf, size_t count,
                       loff_t *ppos) {
    ssize_t ret;
    loff_t pos;

    if (!file || !file->f_op || !file->f_op->write)
        return -EINVAL;

    if (ppos) {
        pos = *ppos;
        ret = file->f_op->write(file, buf, count, &pos);
        if (ret >= 0) {
            *ppos = pos;
            if (ret > 0)
                notifyfs_queue_inode_event(file->f_inode, file->f_inode, NULL,
                                           IN_MODIFY, 0);
        }
        return ret;
    }

    mutex_lock(&file->f_pos_lock);
    pos = file->f_pos;
    if (file->f_flags & O_APPEND)
        pos = (loff_t)file->f_inode->i_size;
    ret = file->f_op->write(file, buf, count, &pos);
    if (ret >= 0) {
        file->f_pos = pos;
        if (ret > 0)
            notifyfs_queue_inode_event(file->f_inode, file->f_inode, NULL,
                                       IN_MODIFY, 0);
    }
    mutex_unlock(&file->f_pos_lock);
    return ret;
}

loff_t vfs_llseek_file(struct vfs_file *file, loff_t offset, int whence) {
    loff_t new_pos;

    if (!file)
        return -EBADF;
    if (file->f_op && file->f_op->llseek)
        return file->f_op->llseek(file, offset, whence);

    mutex_lock(&file->f_pos_lock);
    switch (whence) {
    case SEEK_SET:
        new_pos = offset;
        break;
    case SEEK_CUR:
        new_pos = file->f_pos + offset;
        break;
    case SEEK_END:
        new_pos = (loff_t)file->f_inode->i_size + offset;
        break;
    default:
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }

    if (new_pos < 0) {
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }

    file->f_pos = new_pos;
    mutex_unlock(&file->f_pos_lock);
    return new_pos;
}

int vfs_iterate_dir(struct vfs_file *file, struct vfs_dir_context *ctx) {
    if (!file || !ctx)
        return -EINVAL;
    if (!file->f_op || !file->f_op->iterate_shared)
        return -ENOTDIR;
    return file->f_op->iterate_shared(file, ctx);
}

long vfs_ioctl_file(struct vfs_file *file, unsigned long cmd,
                    unsigned long arg) {
    if (!file)
        return -EBADF;
    if (!file->f_op || !file->f_op->unlocked_ioctl)
        return -ENOTTY;
    return file->f_op->unlocked_ioctl(file, cmd, arg);
}

int vfs_fsync_file(struct vfs_file *file) {
    if (!file)
        return -EBADF;
    if (!file->f_op || !file->f_op->fsync)
        return 0;
    return file->f_op->fsync(file, 0, (loff_t)file->f_inode->i_size, 0);
}

int vfs_poll(vfs_node_t *node, size_t events) {
    struct vfs_file fake = {0};

    if (!node || !node->i_fop || !node->i_fop->poll)
        return -ENOTSUP;

    fake.f_op = node->i_fop;
    fake.f_inode = node;
    fake.node = node;
    return (int)node->i_fop->poll(&fake, NULL) & (int)events;
}

int vfs_truncate_path(const struct vfs_path *path, uint64_t size) {
    struct vfs_kstat stat;
    struct vfs_inode *inode;
    int ret;

    if (!path || !path->dentry || !path->dentry->d_inode)
        return -ENOENT;

    inode = path->dentry->d_inode;
    if (!inode->i_op || !inode->i_op->setattr)
        return -EOPNOTSUPP;

    vfs_fill_generic_kstat(path, &stat);
    stat.size = size;

    ret = inode->i_op->setattr(path->dentry, &stat);
    if (ret == 0)
        notifyfs_queue_inode_event(inode, inode, NULL, IN_MODIFY, 0);
    return ret;
}

int vfs_mkdirat(int dfd, const char *pathname, umode_t mode) {
    struct vfs_path parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *dentry;
    struct vfs_inode *dir;
    int ret;

    ret = vfs_path_parent_lookup(dfd, pathname, LOOKUP_PARENT, &parent, &last,
                                 NULL);
    if (ret < 0)
        return ret;

    dir = parent.dentry ? parent.dentry->d_inode : NULL;
    if (!dir || !dir->i_op || !dir->i_op->mkdir) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    dentry = vfs_d_lookup(parent.dentry, &last);
    if (dentry) {
        if (dentry->d_inode) {
            vfs_dput(dentry);
            ret = -EEXIST;
            goto out;
        }
    } else {
        dentry = vfs_d_alloc(parent.dentry->d_sb, parent.dentry, &last);
        if (!dentry) {
            ret = -ENOMEM;
            goto out;
        }
    }

    ret = dir->i_op->mkdir(dir, dentry, mode);
    if (ret == 0) {
        if (!(dentry->d_flags & VFS_DENTRY_HASHED))
            vfs_d_add(parent.dentry, dentry);
        notifyfs_queue_inode_event(dir, dentry->d_inode, last.name, IN_CREATE,
                                   0);
    }
    vfs_dput(dentry);

out:
    vfs_path_put(&parent);
    vfs_qstr_destroy(&last);
    return ret;
}

int vfs_mknodat(int dfd, const char *pathname, umode_t mode, dev64_t dev) {
    struct vfs_path parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *dentry;
    struct vfs_inode *dir;
    int ret;

    ret = vfs_path_parent_lookup(dfd, pathname, LOOKUP_PARENT, &parent, &last,
                                 NULL);
    if (ret < 0)
        return ret;

    dir = parent.dentry ? parent.dentry->d_inode : NULL;
    if (!dir || !dir->i_op || !dir->i_op->mknod) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    dentry = vfs_d_lookup(parent.dentry, &last);
    if (dentry) {
        if (dentry->d_inode) {
            vfs_dput(dentry);
            ret = -EEXIST;
            goto out;
        }
    } else {
        dentry = vfs_d_alloc(parent.dentry->d_sb, parent.dentry, &last);
        if (!dentry) {
            ret = -ENOMEM;
            goto out;
        }
    }

    ret = dir->i_op->mknod(dir, dentry, mode, dev);
    if (ret == 0) {
        if (!(dentry->d_flags & VFS_DENTRY_HASHED))
            vfs_d_add(parent.dentry, dentry);
        notifyfs_queue_inode_event(dir, dentry->d_inode, last.name, IN_CREATE,
                                   0);
    }
    vfs_dput(dentry);

out:
    vfs_path_put(&parent);
    vfs_qstr_destroy(&last);
    return ret;
}

int vfs_unlinkat(int dfd, const char *pathname, int flags) {
    struct vfs_path parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *victim = NULL;
    struct vfs_inode *dir;
    struct vfs_inode *victim_inode;
    int ret;

    ret = vfs_path_parent_lookup(dfd, pathname, LOOKUP_PARENT, &parent, &last,
                                 NULL);
    if (ret < 0)
        return ret;

    dir = parent.dentry ? parent.dentry->d_inode : NULL;
    victim = vfs_d_lookup(parent.dentry, &last);
    if (!dir || !victim || !victim->d_inode) {
        ret = -ENOENT;
        goto out;
    }

    if ((flags & AT_REMOVEDIR) || S_ISDIR(victim->d_inode->i_mode)) {
        if (!dir->i_op || !dir->i_op->rmdir) {
            ret = -EOPNOTSUPP;
            goto out;
        }
        ret = dir->i_op->rmdir(dir, victim);
    } else {
        if (!dir->i_op || !dir->i_op->unlink) {
            ret = -EOPNOTSUPP;
            goto out;
        }
        ret = dir->i_op->unlink(dir, victim);
    }

    victim_inode = victim->d_inode;
    if (ret == 0) {
        notifyfs_queue_inode_event(dir, victim_inode, victim->d_name.name,
                                   IN_DELETE, 0);
        notifyfs_queue_inode_event(victim_inode, victim_inode, NULL,
                                   IN_DELETE_SELF, 0);
        vfs_dentry_unhash(victim);
        victim->d_flags |= VFS_DENTRY_NEGATIVE;
    }

out:
    if (victim)
        vfs_dput(victim);
    vfs_path_put(&parent);
    vfs_qstr_destroy(&last);
    return ret;
}

int vfs_linkat(int olddfd, const char *oldname, int newdfd, const char *newname,
               int flags) {
    struct vfs_path old_path = {0}, new_parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *new_dentry = NULL;
    struct vfs_inode *new_dir;
    int ret;

    ret = vfs_filename_lookup(olddfd, oldname,
                              (flags & AT_SYMLINK_FOLLOW) ? LOOKUP_FOLLOW : 0,
                              &old_path);
    if (ret < 0)
        return ret;

    ret = vfs_path_parent_lookup(newdfd, newname, LOOKUP_PARENT, &new_parent,
                                 &last, NULL);
    if (ret < 0)
        goto out_old;

    new_dir = new_parent.dentry ? new_parent.dentry->d_inode : NULL;
    if (!new_dir || !new_dir->i_op || !new_dir->i_op->link) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    new_dentry = vfs_d_lookup(new_parent.dentry, &last);
    if (new_dentry) {
        if (new_dentry->d_inode) {
            ret = -EEXIST;
            goto out;
        }
    } else {
        new_dentry =
            vfs_d_alloc(new_parent.dentry->d_sb, new_parent.dentry, &last);
        if (!new_dentry) {
            ret = -ENOMEM;
            goto out;
        }
    }

    ret = new_dir->i_op->link(old_path.dentry, new_dir, new_dentry);
    if (ret == 0) {
        if (!(new_dentry->d_flags & VFS_DENTRY_HASHED))
            vfs_d_add(new_parent.dentry, new_dentry);
        notifyfs_queue_inode_event(new_dir, old_path.dentry->d_inode, last.name,
                                   IN_CREATE, 0);
        notifyfs_queue_inode_event(old_path.dentry->d_inode,
                                   old_path.dentry->d_inode, NULL, IN_ATTRIB,
                                   0);
    }

out:
    if (new_dentry)
        vfs_dput(new_dentry);
    vfs_path_put(&new_parent);
    vfs_qstr_destroy(&last);
out_old:
    vfs_path_put(&old_path);
    return ret;
}

int vfs_symlinkat(const char *target, int newdfd, const char *newname) {
    struct vfs_path parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *dentry = NULL;
    struct vfs_inode *dir;
    int ret;

    ret = vfs_path_parent_lookup(newdfd, newname, LOOKUP_PARENT, &parent, &last,
                                 NULL);
    if (ret < 0)
        return ret;

    dir = parent.dentry ? parent.dentry->d_inode : NULL;
    if (!dir || !dir->i_op || !dir->i_op->symlink) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    dentry = vfs_d_lookup(parent.dentry, &last);
    if (dentry) {
        if (dentry->d_inode) {
            ret = -EEXIST;
            goto out;
        }
    } else {
        dentry = vfs_d_alloc(parent.dentry->d_sb, parent.dentry, &last);
        if (!dentry) {
            ret = -ENOMEM;
            goto out;
        }
    }

    ret = dir->i_op->symlink(dir, dentry, target);
    if (ret == 0) {
        if (!(dentry->d_flags & VFS_DENTRY_HASHED))
            vfs_d_add(parent.dentry, dentry);
        notifyfs_queue_inode_event(dir, dentry->d_inode, last.name, IN_CREATE,
                                   0);
    }

out:
    if (dentry)
        vfs_dput(dentry);
    vfs_path_put(&parent);
    vfs_qstr_destroy(&last);
    return ret;
}

int vfs_renameat2(int olddfd, const char *oldname, int newdfd,
                  const char *newname, unsigned int flags) {
    struct vfs_path old_parent = {0}, new_parent = {0};
    struct vfs_qstr old_last = {0}, new_last = {0};
    struct vfs_dentry *old_dentry = NULL, *new_dentry = NULL;
    struct vfs_rename_ctx ctx;
    struct vfs_inode *moved_inode = NULL;
    int ret;

    mutex_lock(&vfs_rename_lock);

    ret = vfs_path_parent_lookup(olddfd, oldname, LOOKUP_PARENT, &old_parent,
                                 &old_last, NULL);
    if (ret < 0)
        goto out_unlock;
    ret = vfs_path_parent_lookup(newdfd, newname, LOOKUP_PARENT, &new_parent,
                                 &new_last, NULL);
    if (ret < 0)
        goto out;

    old_dentry = vfs_d_lookup(old_parent.dentry, &old_last);
    if (!old_dentry || !old_dentry->d_inode) {
        ret = -ENOENT;
        goto out;
    }

    new_dentry = vfs_d_lookup(new_parent.dentry, &new_last);
    if (!new_dentry) {
        new_dentry =
            vfs_d_alloc(new_parent.dentry->d_sb, new_parent.dentry, &new_last);
        if (!new_dentry) {
            ret = -ENOMEM;
            goto out;
        }
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.old_dir = old_parent.dentry->d_inode;
    ctx.old_dentry = old_dentry;
    ctx.new_dir = new_parent.dentry->d_inode;
    ctx.new_dentry = new_dentry;
    ctx.flags = flags;
    moved_inode = old_dentry->d_inode;

    if (!ctx.old_dir || !ctx.old_dir->i_op || !ctx.old_dir->i_op->rename) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    ret = ctx.old_dir->i_op->rename(&ctx);
    if (ret == 0) {
        uint32_t cookie = notifyfs_next_cookie();

        __atomic_add_fetch(&vfs_rename_seq, 1, __ATOMIC_ACQ_REL);
        notifyfs_queue_inode_event(ctx.old_dir, moved_inode, old_last.name,
                                   IN_MOVED_FROM, cookie);
        notifyfs_queue_inode_event(ctx.new_dir, moved_inode, new_last.name,
                                   IN_MOVED_TO, cookie);
        notifyfs_queue_inode_event(moved_inode, moved_inode, NULL, IN_MOVE_SELF,
                                   cookie);
    }

out:
    if (old_dentry)
        vfs_dput(old_dentry);
    if (new_dentry)
        vfs_dput(new_dentry);
    vfs_path_put(&old_parent);
    vfs_path_put(&new_parent);
    vfs_qstr_destroy(&old_last);
    vfs_qstr_destroy(&new_last);
out_unlock:
    mutex_unlock(&vfs_rename_lock);
    return ret;
}

int vfs_statx(int dfd, const char *pathname, int flags, uint32_t mask,
              struct vfs_kstat *stat) {
    struct vfs_path path = {0};
    int ret;

    ret = vfs_filename_lookup(
        dfd, pathname,
        (flags & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return ret;

    if (path.dentry->d_inode && path.dentry->d_inode->i_op &&
        path.dentry->d_inode->i_op->getattr) {
        ret = path.dentry->d_inode->i_op->getattr(&path, stat, mask, flags);
    } else {
        vfs_fill_generic_kstat(&path, stat);
        ret = 0;
    }

    vfs_path_put(&path);
    return ret;
}

int vfs_kern_mount(const char *fs_name, unsigned long mnt_flags,
                   const char *source, void *data, struct vfs_mount **out) {
    struct vfs_file_system_type *fstype;
    struct vfs_fs_context fc;
    struct vfs_mount *mnt;
    int ret;

    if (!fs_name || !out)
        return -EINVAL;

    fstype = vfs_get_fs_type(fs_name);
    if (!fstype)
        return -ENODEV;

    memset(&fc, 0, sizeof(fc));
    fc.fs_type = fstype;
    fc.mnt_flags = mnt_flags;
    fc.source = source;
    fc.fs_private = data;

    if (fstype->init_fs_context) {
        ret = fstype->init_fs_context(&fc);
        if (ret < 0)
            return ret;
    }

    ret = fstype->get_tree(&fc);
    if (ret < 0)
        return ret;
    if (!fc.sb || !fc.sb->s_root)
        return -EINVAL;

    mnt = vfs_mount_alloc(fc.sb, mnt_flags);
    if (!mnt)
        return -ENOMEM;

    *out = mnt;
    return 0;
}

int vfs_do_mount(int dfd, const char *pathname, const char *fs_name,
                 unsigned long mnt_flags, const char *source, void *data) {
    struct vfs_mount *mnt = NULL;
    struct vfs_path target = {0};
    int ret;

    ret = vfs_kern_mount(fs_name, mnt_flags, source, data, &mnt);
    if (ret < 0)
        return ret;

    ret = vfs_filename_lookup(dfd, pathname,
                              LOOKUP_FOLLOW | LOOKUP_NO_LAST_MOUNT, &target);
    if (ret < 0)
        goto out;

    ret = vfs_mount_attach(target.mnt, target.dentry, mnt);
    if (ret == 0 && !vfs_root_path.mnt) {
        vfs_root_path.mnt = vfs_mntget(mnt);
        vfs_root_path.dentry = vfs_dget(mnt->mnt_root);
    }

out:
    vfs_path_put(&target);
    if (ret < 0 && mnt)
        vfs_mntput(mnt);
    return ret;
}

int vfs_do_move_mount(int from_dfd, const char *from_pathname, int to_dfd,
                      const char *to_pathname) {
    struct vfs_path from = {0};
    struct vfs_path to = {0};
    struct vfs_mount *mnt = NULL;
    int ret;

    if (!from_pathname || !to_pathname)
        return -EINVAL;

    ret = vfs_filename_lookup(from_dfd, from_pathname, LOOKUP_FOLLOW, &from);
    if (ret < 0)
        return ret;

    ret = vfs_filename_lookup(to_dfd, to_pathname,
                              LOOKUP_FOLLOW | LOOKUP_NO_LAST_MOUNT, &to);
    if (ret < 0)
        goto out;

    mnt = vfs_path_mount(&from);
    if (!mnt) {
        ret = -EINVAL;
        goto out;
    }

    ret = vfs_reconfigure_mount(mnt, &to, false);

out:
    if (mnt)
        vfs_mntput(mnt);
    vfs_path_put(&to);
    vfs_path_put(&from);
    return ret;
}

int vfs_do_umount(int dfd, const char *pathname, int flags) {
    struct vfs_path target = {0};
    struct vfs_mount *mnt;
    int ret;

    (void)flags;
    ret = vfs_filename_lookup(dfd, pathname, LOOKUP_FOLLOW, &target);
    if (ret < 0)
        return ret;

    mnt = vfs_path_mount(&target);
    if (!mnt) {
        vfs_path_put(&target);
        return -EINVAL;
    }

    vfs_mount_detach(mnt);
    vfs_path_put(&target);
    vfs_mntput(mnt);
    vfs_mntput(mnt);
    return 0;
}

int vfs_sys_openat(int dfd, const char *pathname,
                   const struct vfs_open_how *how) {
    struct vfs_file *file = NULL;
    int ret;

    ret = vfs_openat(dfd, pathname, how, &file);
    if (ret < 0)
        return ret;

    ret = task_install_file(current_task, file,
                            (how && (how->flags & O_CLOEXEC)) ? FD_CLOEXEC : 0,
                            0);
    if (ret < 0) {
        vfs_file_put(file);
        return ret;
    }

    vfs_file_put(file);
    return ret;
}

int vfs_sys_close(int fd) {
    return task_close_file_descriptor(current_task, fd);
}

ssize_t vfs_sys_read(int fd, void *buf, size_t count) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_read_file(file, buf, count, NULL);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_pread64(int fd, void *buf, size_t count, loff_t pos) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_read_file(file, buf, count, &pos);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_write(int fd, const void *buf, size_t count) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_write_file(file, buf, count, NULL);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_pwrite64(int fd, const void *buf, size_t count, loff_t pos) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_write_file(file, buf, count, &pos);
    vfs_file_put(file);
    return ret;
}
