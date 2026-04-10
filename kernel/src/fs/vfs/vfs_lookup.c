#include "fs/vfs/vfs_internal.h"
#include "task/task.h"

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

static bool vfs_mount_is_same_or_descendant(const struct vfs_mount *root,
                                            const struct vfs_mount *mnt) {
    const struct vfs_mount *cursor;

    if (!root || !mnt)
        return false;

    for (cursor = mnt; cursor; cursor = cursor->mnt_parent) {
        if (cursor == root)
            return true;
        if (!cursor->mnt_parent || cursor->mnt_parent == cursor)
            break;
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
    struct vfs_mount *ns_root_mnt;
    bool root_valid;
    bool pwd_valid;

    if (!start || !root)
        return -EINVAL;
    memset(start, 0, sizeof(*start));
    memset(root, 0, sizeof(*root));

    fs = task_current_vfs_fs();
    ns_root_mnt = current_task ? task_mount_namespace_root(current_task) : NULL;
    if (!fs) {
        if (!vfs_root_path.mnt || !vfs_root_path.dentry)
            return -ENOENT;
        vfs_path_get(&vfs_root_path);
        *root = vfs_root_path;
        while (root->dentry) {
            struct vfs_mount *mounted =
                vfs_child_mount_at(root->mnt, root->dentry);
            if (!mounted)
                break;
            if (!mounted->mnt_root) {
                vfs_mntput(mounted);
                break;
            }
            vfs_path_replace(root, mounted, mounted->mnt_root);
            vfs_mntput(mounted);
        }
        if (vfs_path_is_absolute(name) || dfd == AT_FDCWD) {
            vfs_path_get(root);
            *start = *root;
            return 0;
        }
        vfs_path_put(root);
        return -EBADF;
    }

    root_valid = fs->root.mnt && fs->root.dentry &&
                 (!ns_root_mnt || !ns_root_mnt->mnt_root ||
                  vfs_mount_is_same_or_descendant(ns_root_mnt, fs->root.mnt));
    if (root_valid) {
        vfs_path_get(&fs->root);
        *root = fs->root;
    } else if (ns_root_mnt && ns_root_mnt->mnt_root) {
        root->mnt = vfs_mntget(ns_root_mnt);
        root->dentry = vfs_dget(ns_root_mnt->mnt_root);
    } else if (vfs_root_path.mnt && vfs_root_path.dentry) {
        vfs_path_get(&vfs_root_path);
        *root = vfs_root_path;
    } else {
        return -ENOENT;
    }

    while (root->dentry) {
        struct vfs_mount *mounted = vfs_child_mount_at(root->mnt, root->dentry);
        if (!mounted)
            break;
        if (!mounted->mnt_root) {
            vfs_mntput(mounted);
            break;
        }
        vfs_path_replace(root, mounted, mounted->mnt_root);
        vfs_mntput(mounted);
    }

    if (vfs_path_is_absolute(name)) {
        vfs_path_get(root);
        *start = *root;
        return 0;
    }

    if (dfd == AT_FDCWD) {
        pwd_valid = fs->pwd.mnt && fs->pwd.dentry &&
                    (!ns_root_mnt || !ns_root_mnt->mnt_root ||
                     vfs_mount_is_same_or_descendant(ns_root_mnt, fs->pwd.mnt));
        if (pwd_valid) {
            vfs_path_get(&fs->pwd);
            *start = fs->pwd;
        } else {
            vfs_path_get(root);
            *start = *root;
        }
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

struct vfs_dentry *vfs_lookup_component(struct vfs_path *parent,
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
        if (dentry && !dentry->d_inode) {
            vfs_dentry_unhash(dentry);
            vfs_dput(dentry);
            dentry = NULL;
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

void vfs_follow_mount(struct vfs_path *path) {
    while (path && path->dentry) {
        struct vfs_mount *mounted = vfs_child_mount_at(path->mnt, path->dentry);
        if (!mounted)
            break;
        if (!mounted->mnt_root) {
            vfs_mntput(mounted);
            break;
        }
        vfs_path_replace(path, mounted, mounted->mnt_root);
        vfs_mntput(mounted);
    }
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
    struct vfs_nameidata nd = {0};

    if (depth >= VFS_MAX_SYMLINKS)
        return -ELOOP;
    if (!link_dentry || !link_dentry->d_inode || !link_dentry->d_inode->i_op ||
        !link_dentry->d_inode->i_op->get_link) {
        return -ELOOP;
    }

    target = link_dentry->d_inode->i_op->get_link(link_dentry,
                                                  link_dentry->d_inode, &nd);
    if (IS_ERR_OR_NULL(target))
        return target ? (int)PTR_ERR(target) : -ENOENT;

    if (nd.path.mnt && nd.path.dentry) {
        if (!remaining || !remaining[0]) {
            *out = nd.path;
            return 0;
        }

        ret = __vfs_filename_lookup(&nd.path, &nd.path, remaining, lookup_flags,
                                    depth + 1, out);
        vfs_path_put(&nd.path);
        return ret;
    }

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
        vfs_follow_mount(&next);
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
    vfs_follow_mount(&path);

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

        vfs_follow_mount(&path);

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
        vfs_follow_mount(parent);
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
    if (ret == 0)
        vfs_follow_mount(parent);
    if (type)
        *type = 0;
    free(copy);
    return ret;
}
