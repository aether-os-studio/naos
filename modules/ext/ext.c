// Copyright (C) 2025  lihanrui2913
#include <ext.h>
#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>

static int ext_fsid = 0;

spinlock_t rwlock = SPIN_INIT;

extern uint64_t device_dev_nr;

int ext_mount(uint64_t dev, vfs_node_t node) {
    spin_lock(&rwlock);

    device_dev_nr = dev;

    ext4_device_register(device_dev_get(), "dev");

    device_dev_name_set("dev");

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

        uint64_t nodes_count = 0;
        list_foreach(node->child, i) { nodes_count++; }
        vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
        uint64_t idx = 0;
        list_foreach(node->child, i) { nodes[idx++] = (vfs_node_t)i->data; }
        for (uint64_t i = 0; i < idx; i++) {
            vfs_free(nodes[i]);
        }
        free(nodes);
    }
}

void ext_open(void *parent, const char *name, vfs_node_t node) {
    spin_lock(&rwlock);

    ext_handle_t *handle = malloc(sizeof(ext_handle_t));
    handle->node = node;
    char *path = vfs_get_fullpath(node);
    if (node->type & file_dir) {
        handle->dir = malloc(sizeof(ext4_dir));
        int ret = ext4_dir_open(handle->dir, (const char *)path);
        if (ret != 0) {
            printk("Failed to open dir %s\n", path);
            free(path);
            free(handle);
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
        ext4_fopen(handle->file, (const char *)path, "r+b");
        node->size = ext4_fsize(handle->file);
    } else {
        handle->ptr = NULL;
    }

    uint32_t mode = 0;
    ext4_mode_get((const char *)path, &mode);
    node->mode = mode;
    node->handle = handle;

    free(path);

    spin_unlock(&rwlock);
}

bool ext_close(void *current) {
    spin_lock(&rwlock);
    ext_handle_t *handle = current;
    if (handle->node->type & file_dir)
        ext4_dir_close(handle->dir);
    else if (handle->node->type & file_none)
        ext4_fclose(handle->file);
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
    vfs_node_t to_node = vfs_open_at(node->parent, (const char *)tmp);
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

int ext_mkfile(void *parent, const char *name, vfs_node_t node) {
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);

    ext4_file f;
    int ret = ext4_fopen2(&f, (const char *)buf, O_CREAT);
    ext4_fclose(&f);

    if (!ret) {
        ext4_mode_set(buf, 0700);
        node->mode = 0700;
    }

    free(buf);

    spin_unlock(&rwlock);

    return ret;
}

int ext_link(void *parent, const char *name, vfs_node_t node) { return 0; }

int ext_symlink(void *parent, const char *name, vfs_node_t node) {
    spin_lock(&rwlock);

    char *fullpath = vfs_get_fullpath(node);

    int ret = ext4_fsymlink(name, fullpath);

    ext4_mode_set(name, 0700);

    node->mode = 0700;

    free(fullpath);

    spin_unlock(&rwlock);

    vfs_node_t target = vfs_open_at(node->parent, name);
    if (target) {
        node->size = target->size;
    }

    return ret;
}

int ext_mknod(void *parent, const char *name, vfs_node_t node, uint16_t mode,
              int dev) {
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

    node->mode = 0700;

    free(fullpath);

    spin_unlock(&rwlock);

    return ret;
}

int ext_mkdir(void *parent, const char *name, vfs_node_t node) {
    spin_lock(&rwlock);

    char *buf = vfs_get_fullpath(node);

    int ret = ext4_dir_mk((const char *)buf);

    if (!ret) {
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

int ext_delete(void *parent, vfs_node_t node) {
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

int ext_rename(void *current, const char *new) {
    spin_lock(&rwlock);

    ext_handle_t *handle = current;
    char *path = vfs_get_fullpath(handle->node);
    int ret = ext4_frename((const char *)path, new);
    free(path);

    spin_unlock(&rwlock);

    return ret;
}

int ext_stat(void *file, vfs_node_t node) {
    ext_handle_t *handle = file;
    spin_lock(&rwlock);
    if (node->type & file_symlink) {
        char *fpath = vfs_get_fullpath(node);
        char linkpath[1024];
        memset(linkpath, 0, sizeof(linkpath));
        int r = ext4_readlink(fpath, linkpath, sizeof(linkpath), NULL);
        spin_unlock(&rwlock);
        vfs_node_t target = vfs_open_at(node->parent, (const char *)linkpath);
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

int ext_ioctl(void *file, ssize_t cmd, ssize_t arg) { return 0; }

int ext_poll(void *file, size_t events) { return 0; }

void ext_resize(void *current, uint64_t size) {
    spin_lock(&rwlock);
    ext_handle_t *handle = current;
    if (handle->node->type & file_none) {
        handle->node->size = ext4_ftruncate(handle->file, size);
    }
    spin_unlock(&rwlock);
}

void *ext_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
              size_t flags) {
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

vfs_node_t ext_dup(vfs_node_t node) { return node; }

void ext_free_handle(ext_handle_t *handle) { free(handle); }

static struct vfs_callback callbacks = {
    .mount = ext_mount,
    .unmount = ext_unmount,
    .open = ext_open,
    .close = (vfs_close_t)ext_close,
    .read = (vfs_read_t)ext_read,
    .write = (vfs_write_t)ext_write,
    .readlink = (vfs_readlink_t)ext_readlink,
    .mkdir = ext_mkdir,
    .mkfile = ext_mkfile,
    .link = ext_link,
    .symlink = ext_symlink,
    .mknod = ext_mknod,
    .chmod = ext_chmod,
    .chown = ext_chown,
    .delete = (vfs_del_t)ext_delete,
    .rename = (vfs_rename_t)ext_rename,
    .map = (vfs_mapfile_t)ext_map,
    .stat = ext_stat,
    .ioctl = ext_ioctl,
    .poll = ext_poll,
    .resize = (vfs_resize_t)ext_resize,

    .free_handle = (vfs_free_handle_t)ext_free_handle,
};

fs_t extfs = {
    .name = "ext",
    .magic = 0,
    .callback = &callbacks,
    .flags = 0,
};

__attribute__((visibility("default"))) void dlmain() {
    ext_fsid = vfs_regist(&extfs);
}
