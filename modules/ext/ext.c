// Copyright (C) 2025  lihanrui2913
#include <ext.h>
#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>

static int ext_fsid = 0;

spinlock_t rwlock = {0};

extern vfs_node_t dev_node;

int ext_mount(vfs_node_t dev, vfs_node_t node) {
    spin_lock(&rwlock);

    dev_node = dev;

    ext4_device_register(vfs_dev_get(), "dev");

    vfs_dev_name_set("dev");

    char *fullpath = vfs_get_fullpath(node);
    int ret = ext4_mount("dev", (const char *)fullpath, false);

    if (ret != 0) {
        ext4_device_unregister("dev");
        free(fullpath);
        spin_unlock(&rwlock);
        return -1;
    }

    ext4_dir *dir = malloc(sizeof(ext4_dir));
    ext4_dir_open(dir, (const char *)fullpath);

    free(fullpath);

    const ext4_direntry *entry;
    while ((entry = ext4_dir_entry_next(dir))) {
        if (!strcmp((const char *)entry->name, ".") ||
            !strcmp((const char *)entry->name, ".."))
            continue;
        if (vfs_child_find(node, (const char *)entry->name))
            continue;
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
    node->handle = handle;

    spin_unlock(&rwlock);

    return ret;
}

void ext_unmount(vfs_node_t node) {
    // TODO
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
            if (vfs_child_find(node, (const char *)entry->name)) {
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
        char *path = vfs_get_fullpath(node);
        char *buf = malloc(2048);
        size_t rcnt = 0;
        ext4_readlink((const char *)path, buf, 2048, &rcnt);
        free(path);
        buf[rcnt] = '\0';
        spin_unlock(&rwlock);
        node->linkto = vfs_open_at(node->parent, buf);
        spin_lock(&rwlock);
        if (node->linkto) {
            node->linkto->refcount++;
            node->size = node->linkto->size;

            ext_handle_t *target_handle = node->linkto->handle;
            handle->file = target_handle->file;
        }
    } else {
        handle->file = malloc(sizeof(ext4_file));
        ext4_fopen(handle->file, (const char *)path, "r+b");
        node->size = ext4_fsize(handle->file);
    }

    uint32_t mode = 0;
    ext4_mode_get((const char *)path, &mode);
    node->mode = mode;
    node->handle = handle;

    free(path);

    spin_unlock(&rwlock);
}

bool ext_close(void *current) {
    ext_handle_t *handle = current;
    if (handle->node->type & file_dir)
        ext4_dir_close(handle->dir);
    else
        ext4_fclose(handle->file);
    free(current);
    return true;
}

ssize_t ext_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    spin_lock(&rwlock);

    void *file = fd->node->handle;

    ssize_t ret = 0;
    ext_handle_t *handle = file;
    if (!handle || !handle->node || !handle->file)
        return -1;
    if ((handle->node->type & file_symlink) && handle->node->linkto)
        handle = handle->node->linkto->handle;
    if (offset > handle->node->size) {
        uint8_t *buffer = alloc_frames_bytes(offset - handle->node->size);
        memset(buffer, 0, offset - handle->node->size);
        ext4_fseek(handle->file, (int64_t)handle->node->size,
                   (uint32_t)SEEK_SET);
        ext4_fwrite(handle->file, addr, offset - handle->node->size,
                    (size_t *)&ret);
        free_frames_bytes(buffer, offset - handle->node->size);
    }
    ext4_fseek(handle->file, (int64_t)offset, (uint32_t)SEEK_SET);
    ext4_fwrite(handle->file, addr, size, (size_t *)&ret);
    handle->node->size = ext4_fsize(handle->file);
    fd->node->size = ext4_fsize(handle->file);

    spin_unlock(&rwlock);

    return ret;
}

ssize_t ext_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    spin_lock(&rwlock);

    void *file = fd->node->handle;

    ssize_t ret = 0;
    ext_handle_t *handle = file;
    if (!handle || !handle->node)
        return -1;
    if ((handle->node->type & file_symlink) && fd->node->linkto) {
        ext_handle_t *target_handle = fd->node->linkto->handle;
        if (target_handle && target_handle->file) {
            ext4_fseek(target_handle->file, (int64_t)offset,
                       (uint32_t)SEEK_SET);
            ext4_fread(target_handle->file, addr, size, (size_t *)&ret);
        } else {
            printk("%s: symlink doesn't has a target file\n", __func__);
        }
    } else {
        ext4_fseek(handle->file, (int64_t)offset, (uint32_t)SEEK_SET);
        ext4_fread(handle->file, addr, size, (size_t *)&ret);
    }
    spin_unlock(&rwlock);
    return ret;
}

ssize_t ext_readlink(vfs_node_t node, void *addr, size_t offset, size_t size) {
    vfs_node_t linkto = node->linkto;

    if (!linkto) {
        return -ENOLINK;
    }

    char *current_path = vfs_get_fullpath(node);
    char *linkto_path = vfs_get_fullpath(linkto);

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    rel_status status =
        calculate_relative_path(buf, current_path, linkto_path, sizeof(buf));

    free(current_path);
    free(linkto_path);

    int len = strnlen(buf, size);
    memcpy(addr, buf, len);
    return len;
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
    int ret = ext4_fremove((const char *)path);
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
    if (handle->node->type & file_none) {
        handle->node->size = ext4_fsize(handle->file);
    }

    return 0;
}

int ext_ioctl(void *file, ssize_t cmd, ssize_t arg) { return -EINVAL; }

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
    return general_map((vfs_read_t)ext_read, file, (uint64_t)addr, size, prot,
                       flags, offset);
}

vfs_node_t ext_dup(vfs_node_t node) { return node; }

void ext_free_handle(ext_handle_t *handle) {}

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
    .dup = (vfs_dup_t)ext_dup,

    .free_handle = (vfs_free_handle_t)ext_free_handle,
};

fs_t extfs = {
    .name = "ext",
    .magic = 0,
    .callback = &callbacks,
};

__attribute__((visibility("default"))) void dlmain() {
    ext_fsid = vfs_regist(&extfs);
}
