// Copyright (C) 2025-2026  lihanrui2913
#include <ext.h>
#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>

static int ext_fsid = 0;

spinlock_t rwlock = SPIN_INIT;

extern uint64_t device_dev_nr;

char *get_mp(vfs_node_t node) {
    char *mount_point = vfs_get_fullpath(node);
    size_t mp_len = strlen(mount_point);
    if (mount_point[mp_len - 1] != '/') {
        char *new_mount_point = malloc(mp_len + 2);
        strcpy(new_mount_point, mount_point);
        new_mount_point[mp_len] = '/';
        new_mount_point[mp_len + 1] = '\0';
        free(mount_point);
        mount_point = new_mount_point;
    }
    return mount_point;
}

static void ext_prune_children(vfs_node_t parent, const char *name) {
    if (!parent || !name)
        return;

    uint64_t nodes_count = 0;
    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        if (child == child->root)
            continue;
        nodes_count++;
    }

    if (!nodes_count)
        return;

    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    if (!nodes)
        return;

    uint64_t idx = 0;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        if (child == child->root)
            continue;
        nodes[idx++] = child;
    }

    for (uint64_t i = 0; i < idx; i++) {
        vfs_free(nodes[i]);
    }

    free(nodes);
}

int ext_mount(uint64_t dev, vfs_node_t node) {
    spin_lock(&rwlock);

    device_dev_nr = dev;

    ext4_device_register(device_dev_get(), "dev");

    device_dev_name_set("dev");

    char *mount_point = get_mp(node);

    int ret = ext4_mount("dev", (const char *)mount_point, false);
    if (ret != 0) {
        ext4_device_unregister("dev");
        free(mount_point);
        spin_unlock(&rwlock);
        return -ret;
    }

    ext4_dir *dir = malloc(sizeof(ext4_dir));
    ext4_dir_open(dir, (const char *)mount_point);

    free(mount_point);

    const ext4_direntry *entry;
    while ((entry = ext4_dir_entry_next(dir))) {
        if (!strcmp((const char *)entry->name, ".") ||
            !strcmp((const char *)entry->name, ".."))
            continue;
        vfs_node_t exist = vfs_child_find(node, (const char *)entry->name);
        if (exist) {
            if (exist == exist->root) {
                continue;
            }
        }
        vfs_node_t child =
            vfs_child_append(node, (const char *)entry->name, NULL);
        child->inode = (uint64_t)entry->inode;
        child->fsid = ext_fsid;
        if (entry->inode_type == EXT4_DE_SYMLINK)
            child->type = file_symlink;
        else if (entry->inode_type == EXT4_DE_DIR)
            child->type = file_dir;
        else
            child->type = file_none;
    }

    ext4_dir_close(dir);

    ext_handle_t *handle = malloc(sizeof(ext_handle_t));
    handle->dir = dir;
    handle->node = node;

    node->inode = EXT4_ROOT_INO;
    node->fsid = ext_fsid;
    node->dev = device_dev_nr;
    node->rdev = device_dev_nr;
    node->handle = handle;

    spin_unlock(&rwlock);

    return ret;
}

void ext_unmount(vfs_node_t node) {
    if (node) {
        char *mp_path = vfs_get_fullpath(node);
        ext4_umount((const char *)mp_path);
        node->dev = node->parent ? node->parent->dev : 0;
        node->rdev = node->parent ? node->parent->rdev : 0;

        vfs_node_t child, tmp;
        uint64_t nodes_count = 0;
        llist_for_each(child, tmp, &node->childs, node_for_childs) {
            nodes_count++;
        }
        vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
        uint64_t idx = 0;
        llist_for_each(child, tmp, &node->childs, node_for_childs) {
            nodes[idx++] = child;
        }
        for (uint64_t i = 0; i < idx; i++) {
            vfs_free(nodes[i]);
        }
        free(nodes);
    }
}

int ext_remount(vfs_node_t old, vfs_node_t node) {
    spin_lock(&rwlock);

    char *old_mp_path = get_mp(old);
    char *new_mp_path = get_mp(node);

    int ret =
        ext4_remount((const char *)old_mp_path, (const char *)new_mp_path);
    if (ret != 0) {
        free(old_mp_path);
        free(new_mp_path);
        spin_unlock(&rwlock);
        return -ret;
    }

    if (old->parent == node) {
        llist_delete(&old->node_for_childs);
        old->parent = NULL;
    }

    vfs_merge_nodes_to(node, old);

    ext4_dir *dir = malloc(sizeof(ext4_dir));
    ext4_dir_open(dir, (const char *)new_mp_path);

    const ext4_direntry *entry;
    while ((entry = ext4_dir_entry_next(dir))) {
        if (!strcmp((const char *)entry->name, ".") ||
            !strcmp((const char *)entry->name, ".."))
            continue;
        vfs_node_t exist = vfs_child_find(node, (const char *)entry->name);
        if (exist) {
            if (exist == exist->root) {
                ext_prune_children(node, (const char *)entry->name);
                continue;
            }
            vfs_free(exist);
        }
        vfs_node_t child =
            vfs_child_append(node, (const char *)entry->name, NULL);
        child->inode = (uint64_t)entry->inode;
        child->fsid = ext_fsid;
        if (entry->inode_type == EXT4_DE_SYMLINK)
            child->type = file_symlink;
        else if (entry->inode_type == EXT4_DE_DIR)
            child->type = file_dir;
        else
            child->type = file_none;
    }

    ext4_dir_close(dir);

    free(old_mp_path);
    free(new_mp_path);

    spin_unlock(&rwlock);

    return ret;
}

void ext_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    (void)name;
    spin_lock(&rwlock);

    ext_handle_t *handle = malloc(sizeof(ext_handle_t));
    handle->node = node;
    char *path = vfs_get_fullpath(node);
    if (node->type & file_dir) {
        handle->dir = malloc(sizeof(ext4_dir));
        int ret = ext4_dir_open(handle->dir, (const char *)path);
        if (ret != 0) {
            printk("Failed to open directory: %s\n", path);
            free(handle->dir);
            free(handle);
            free(path);
            spin_unlock(&rwlock);
            return;
        }

        const ext4_direntry *entry;
        while ((entry = ext4_dir_entry_next(handle->dir))) {
            if (!strcmp((const char *)entry->name, ".") ||
                !strcmp((const char *)entry->name, ".."))
                continue;
            if (vfs_child_find(node, (const char *)entry->name) &&
                entry->inode_type != EXT4_DE_DIR) {
                continue;
            }
            vfs_node_t child =
                vfs_child_append(node, (const char *)entry->name, NULL);
            child->fsid = ext_fsid;
            child->inode = (uint64_t)entry->inode;
            if (entry->inode_type == EXT4_DE_SYMLINK)
                child->type = file_symlink;
            else if (entry->inode_type == EXT4_DE_DIR)
                child->type = file_dir;
            else
                child->type = file_none;
        }

        ext4_dir_entry_rewind(handle->dir);
    } else if (node->type & file_symlink) {
        handle->ptr = NULL;
    } else if (node->type & file_none) {
        handle->file = malloc(sizeof(ext4_file));
        int ret = ext4_fopen(handle->file, (const char *)path, "r+b");
        if (ret != 0) {
            printk("Failed to open file: %s\n", path);
            free(handle->file);
            free(handle);
            free(path);
            spin_unlock(&rwlock);
            return;
        }
        node->size = ext4_fsize(handle->file);
    } else {
        handle->ptr = NULL;
    }

    uint32_t mode = 0;
    ext4_mode_get((const char *)path, &mode);
    node->mode = mode;
    node->handle = handle;
    uint32_t t = 0;
    ext4_ctime_get((const char *)path, &t);
    node->createtime = t;
    ext4_mtime_get((const char *)path, &t);
    node->readtime = t;

    free(path);

    spin_unlock(&rwlock);
}

bool ext_close(vfs_node_t node) {
    ext_handle_t *handle = node ? node->handle : NULL;
    if (!handle) {
        return true;
    }
    spin_lock(&rwlock);
    if (handle->node->type & file_dir)
        ext4_dir_close(handle->dir);
    else if (handle->node->type & file_none)
        ext4_fclose(handle->file);
    free(handle->ptr);
    handle->ptr = NULL;
    handle->node->handle = NULL;
    free(handle);
    spin_unlock(&rwlock);
    return true;
}

ssize_t ext_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    spin_lock(&rwlock);

    ssize_t ret = 0;
    ext_handle_t *handle = fd->node->handle;
    ext4_file *file = NULL;
    if (!handle || !handle->node) {
        ret = -ENOENT;
        goto rollback;
    }

    file = handle->file;
    if (!file) {
        ret = -EINVAL;
        goto rollback;
    }

    if (offset > handle->node->size) {
        uint8_t *buffer = alloc_frames_bytes(offset - handle->node->size);
        memset(buffer, 0, offset - handle->node->size);
        ext4_fseek(file, (int64_t)handle->node->size, (uint32_t)SEEK_SET);
        ext4_fwrite(file, buffer, offset - handle->node->size, (size_t *)&ret);
        free_frames_bytes(buffer, offset - handle->node->size);
    }
    ext4_fseek(file, (int64_t)offset, (uint32_t)SEEK_SET);
    int r = ext4_fwrite(file, addr, size, (size_t *)&ret);
    if (r) {
        ret = -r;
        goto rollback;
    }
    fd->node->size = ext4_fsize(file);

rollback:
    spin_unlock(&rwlock);

    return ret;
}

ssize_t ext_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    spin_lock(&rwlock);

    ssize_t ret = 0;
    ext_handle_t *handle = fd->node->handle;
    ext4_file *file = NULL;
    if (!handle || !handle->node) {
        ret = -ENOENT;
        goto rollback;
    }

    file = handle->file;
    if (!file) {
        ret = -EINVAL;
        goto rollback;
    }

    ext4_fseek(file, (int64_t)offset, (uint32_t)SEEK_SET);
    int r = ext4_fread(file, addr, size, (size_t *)&ret);
    if (r) {
        ret = -r;
        goto rollback;
    }

rollback:
    spin_unlock(&rwlock);

    return ret;
}

ssize_t ext_readlink(vfs_node_t node, void *addr, size_t offset, size_t size) {
    spin_lock(&rwlock);
    char tmp[1024];
    memset(tmp, 0, sizeof(tmp));
    char *node_path = vfs_get_fullpath(node);
    ext4_readlink(node_path, tmp, sizeof(tmp), NULL);
    free(node_path);

    spin_unlock(&rwlock);
    vfs_node_t to_node = vfs_open_at(node->parent, (const char *)tmp, 0);
    if (!to_node) {
        return -ENOENT;
    }
    spin_lock(&rwlock);

    char *from_path = vfs_get_fullpath(node);
    char *to_path = vfs_get_fullpath(to_node);

    char output[1024];
    memset(output, 0, sizeof(output));
    calculate_relative_path(output, from_path, to_path, size);
    free(from_path);
    free(to_path);

    ssize_t to_copy = MIN(size, strlen(output));
    memcpy(addr, output, to_copy);

    spin_unlock(&rwlock);

    return to_copy;
}

int ext_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    (void)name;
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);

    ext4_file f;
    int ret = ext4_fopen2(&f, (const char *)buf, O_CREAT);
    ext4_fclose(&f);

    if (!ret) {
        tm time;
        time_read(&time);
        int64_t timespec = mktime(&time);
        ext4_ctime_set(buf, timespec);
        ext4_mtime_set(buf, timespec);
        ext4_mode_set(buf, 0700);
        node->mode = 0700;
    }

    free(buf);

    spin_unlock(&rwlock);

    return ret;
}

int ext_link(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    (void)name;
    (void)node;
    return 0;
}

int ext_symlink(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    spin_lock(&rwlock);

    char *fullpath = vfs_get_fullpath(node);

    int ret = ext4_fsymlink(name, fullpath);

    ext4_mode_set(name, 0700);

    tm time;
    time_read(&time);
    int64_t timespec = mktime(&time);
    ext4_ctime_set(fullpath, timespec);
    ext4_mtime_set(fullpath, timespec);

    node->mode = 0700;

    free(fullpath);

    spin_unlock(&rwlock);

    vfs_node_t target = vfs_open_at(node->parent, name, 0);
    if (target) {
        node->size = target->size;
    }

    return ret;
}

int ext_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
              uint16_t mode, int dev) {
    (void)parent;
    (void)name;
    spin_lock(&rwlock);

    char *fullpath = vfs_get_fullpath(node);

    int ftype = 0;
    switch (mode & S_IFMT) {
    case S_IFBLK:
        ftype = EXT4_DE_BLKDEV;
        break;
    case S_IFCHR:
        ftype = EXT4_DE_CHRDEV;
        break;
    case S_IFIFO:
        ftype = EXT4_DE_FIFO;
        break;
    default:
        ftype = EXT4_DE_UNKNOWN;
        break;
    }

    int ret = ext4_mknod(fullpath, ftype, dev);

    ext4_mode_set(fullpath, 0700);

    tm time;
    time_read(&time);
    int64_t timespec = mktime(&time);
    ext4_ctime_set(fullpath, timespec);
    ext4_mtime_set(fullpath, timespec);

    node->mode = 0700;

    free(fullpath);

    spin_unlock(&rwlock);

    return -ret;
}

int ext_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    (void)name;
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);

    int ret = ext4_dir_mk((const char *)buf);

    if (!ret) {
        tm time;
        time_read(&time);
        int64_t timespec = mktime(&time);
        ext4_ctime_set(buf, timespec);
        ext4_mtime_set(buf, timespec);
        ext4_mode_set(buf, 0700);
        node->mode = 0700;
    }

    free(buf);

    spin_unlock(&rwlock);

    return ret;
}

int ext_chmod(vfs_node_t node, uint16_t mode) {
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);
    int ret = ext4_mode_set(buf, mode);
    free(buf);

    if (!ret)
        node->mode = mode;

    spin_unlock(&rwlock);

    return ret;
}

int ext_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);
    int ret = ext4_owner_set(buf, uid, gid);
    free(buf);

    if (!ret) {
        node->owner = uid;
        node->group = gid;
    }

    spin_unlock(&rwlock);

    return ret;
}

int ext_delete(vfs_node_t parent, vfs_node_t node) {
    (void)parent;
    spin_lock(&rwlock);

    char *path = vfs_get_fullpath(node);
    int ret;
    if (node->type & file_dir)
        ret = ext4_dir_rm((const char *)path);
    else
        ret = ext4_fremove((const char *)path);
    free(path);

    spin_unlock(&rwlock);

    return ret;
}

int ext_rename(vfs_node_t node, const char *new) {
    if (!node || !node->handle) {
        return -ENOENT;
    }

    spin_lock(&rwlock);

    char *path = vfs_get_fullpath(node);
    int ret = ext4_frename((const char *)path, new);
    free(path);

    spin_unlock(&rwlock);

    return ret;
}

int ext_stat(vfs_node_t node) {
    ext_handle_t *handle = node ? node->handle : NULL;
    if (!node || !handle)
        return -ENOENT;
    spin_lock(&rwlock);
    if (node->type & file_symlink) {
        char *fpath = vfs_get_fullpath(node);
        char linkpath[1024];
        memset(linkpath, 0, sizeof(linkpath));
        int r = ext4_readlink(fpath, linkpath, sizeof(linkpath), NULL);
        spin_unlock(&rwlock);
        vfs_node_t target =
            vfs_open_at(node->parent, (const char *)linkpath, 0);
        spin_lock(&rwlock);
        if (target) {
            node->size = target->size;
        }
        free(fpath);
    } else if (node->type & file_none) {
        node->size = ext4_fsize(handle->file);
    }
    spin_unlock(&rwlock);

    return 0;
}

int ext_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    (void)node;
    (void)cmd;
    (void)arg;
    return 0;
}

int ext_poll(vfs_node_t node, size_t events) {
    (void)node;
    (void)events;
    return 0;
}

void ext_resize(vfs_node_t node, uint64_t size) {
    ext_handle_t *handle = node ? node->handle : NULL;
    if (!handle) {
        return;
    }
    spin_lock(&rwlock);
    if (handle->node->type & file_none) {
        ext4_ftruncate(handle->file, size);
        handle->node->size = size;
    }
    spin_unlock(&rwlock);
}

void *ext_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
              size_t flags) {
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

vfs_node_t ext_dup(vfs_node_t node) { return node; }

void ext_free_handle(vfs_node_t node) {
    if (!node || !node->handle)
        return;
    free(node->handle);
    node->handle = NULL;
}

static vfs_operations_t ext_vfs_ops = {
    .mount = ext_mount,
    .unmount = ext_unmount,
    .remount = ext_remount,
    .open = ext_open,
    .close = ext_close,
    .read = ext_read,
    .write = ext_write,
    .readlink = ext_readlink,
    .mkdir = ext_mkdir,
    .mkfile = ext_mkfile,
    .link = ext_link,
    .symlink = ext_symlink,
    .mknod = ext_mknod,
    .chmod = ext_chmod,
    .chown = ext_chown,
    .delete = ext_delete,
    .rename = ext_rename,
    .map = ext_map,
    .stat = ext_stat,
    .ioctl = ext_ioctl,
    .poll = ext_poll,
    .resize = ext_resize,

    .free_handle = ext_free_handle,
};

fs_t extfs = {
    .name = "ext",
    .magic = 0,
    .ops = &ext_vfs_ops,
    .flags = 0,
};

__attribute__((visibility("default"))) void dlmain() {
    ext_fsid = vfs_regist(&extfs);
}
