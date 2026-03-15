#include <fs/vfs/vfs.h>
#include <fs/vfs/tmp.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <fs/vfs/tmpfs_limit.h>

#define MAX_TMPFS_FILE_SIZE (64 * 1024 * 1024) // 64MB

int tmpfs_fsid = 0;

spinlock_t tmpfs_oplock = SPIN_INIT;
spinlock_t tmpfs_mem_limit_lock = SPIN_INIT;
uint64_t tmpfs_mem_used = 0;

extern uint32_t device_number;

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
        if (delta >= tmpfs_mem_used) {
            tmpfs_mem_used = 0;
        } else {
            tmpfs_mem_used -= delta;
        }
    }

    spin_unlock(&tmpfs_mem_limit_lock);
    return 0;
}

void tmpfs_mem_release(uint64_t size) {
    if (size == 0)
        return;

    spin_lock(&tmpfs_mem_limit_lock);

    uint64_t aligned = tmpfs_mem_align(size);
    if (aligned >= tmpfs_mem_used) {
        tmpfs_mem_used = 0;
    } else {
        tmpfs_mem_used -= aligned;
    }

    spin_unlock(&tmpfs_mem_limit_lock);
}

static int tmpfs_replace_content(tmpfs_node_t *handle, size_t new_capability,
                                 size_t preserve_size, bool zero_tail) {
    uint64_t old_capability =
        (handle && handle->content) ? handle->capability : 0;

    if (!handle)
        return -EINVAL;

    if (new_capability == old_capability)
        return 0;

    int ret = tmpfs_mem_resize_reserve(old_capability, new_capability);
    if (ret != 0)
        return ret;

    void *new_content = NULL;
    if (new_capability > 0) {
        new_content = alloc_frames_bytes(new_capability);
        if (!new_content) {
            tmpfs_mem_resize_reserve(new_capability, old_capability);
            return -ENOMEM;
        }

        if (handle->content && preserve_size > 0) {
            memcpy(new_content, handle->content,
                   MIN((size_t)old_capability,
                       MIN(preserve_size, new_capability)));
        }

        if (zero_tail && new_capability > preserve_size) {
            memset((uint8_t *)new_content + preserve_size, 0,
                   new_capability - preserve_size);
        }
    }

    if (handle->content && old_capability > 0)
        free_frames_bytes(handle->content, old_capability);

    handle->content = new_content;
    handle->capability = new_capability;
    return 0;
}

void tmpfs_open(vfs_node_t parent, const char *name, vfs_node_t node) {}

bool tmpfs_close(vfs_node_t node) { return false; }

ssize_t tmpfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd->flags);
    }

    tmpfs_node_t *handle = fd->node->handle;
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t tmpfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_write(fd->node->rdev, (void *)addr, offset, size,
                            fd->flags);
    }

    spin_lock(&tmpfs_oplock);
    tmpfs_node_t *handle = fd->node->handle;
    if (offset > SIZE_MAX - size) {
        spin_unlock(&tmpfs_oplock);
        return -EFBIG;
    }
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        if (new_capability > MAX_TMPFS_FILE_SIZE) {
            spin_unlock(&tmpfs_oplock);
            return -EFBIG;
        }
        if (tmpfs_replace_content(handle, new_capability, handle->capability,
                                  false) != 0) {
            spin_unlock(&tmpfs_oplock);
            return -ENOMEM;
        }
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    spin_unlock(&tmpfs_oplock);
    return size;
}

ssize_t tmpfs_readlink(vfs_node_t node, void *addr, size_t offset,
                       size_t size) {
    tmpfs_node_t *handle = node->handle;
    if (offset >= handle->size)
        return 0;

    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

int tmpfs_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int tmpfs_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    tmpfs_node_t *handle = calloc(1, sizeof(tmpfs_node_t));
    if (!handle)
        return -ENOMEM;
    handle->capability = DEFAULT_PAGE_SIZE;
    if (tmpfs_replace_content(handle, handle->capability, 0, true) != 0) {
        free(handle);
        return -ENOMEM;
    }
    handle->size = 0;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int tmpfs_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
                uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    if (node->handle) {
        return -EEXIST;
    }
    tmpfs_node_t *handle = calloc(1, sizeof(tmpfs_node_t));
    if (!handle)
        return -ENOMEM;
    handle->capability = DEFAULT_PAGE_SIZE;
    if (tmpfs_replace_content(handle, handle->capability, 0, true) != 0) {
        free(handle);
        return -ENOMEM;
    }
    handle->size = 0;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int tmpfs_symlink(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    tmpfs_node_t *handle = calloc(1, sizeof(tmpfs_node_t));
    if (!handle)
        return -ENOMEM;
    size_t len = strlen(name);
    handle->capability = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    if (tmpfs_replace_content(handle, handle->capability, 0, true) != 0) {
        free(handle);
        return -ENOMEM;
    }
    memcpy(handle->content, name, len);
    handle->size = len;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int tmpfs_mount(uint64_t dev, vfs_node_t node) {
    spin_lock(&tmpfs_oplock);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = tmpfs_fsid;
    node->dev = (TMPFS_DEV_MAJOR << 8) | 0;
    node->rdev = (TMPFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&tmpfs_oplock);

    return 0;
}

void tmpfs_unmount(vfs_node_t root) {
    root->fsid = (uint32_t)(root->flags >> 32);

    vfs_node_t node, tmp;
    llist_for_each(node, tmp, &root->childs, node_for_childs) {
        if (node == node->root) {
            char *node_path = vfs_get_fullpath(node);
            vfs_unmount((const char *)node_path);
            free(node_path);
        }
    }

    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    uint64_t nodes_count = 0;
    llist_for_each(node, tmp, &root->childs, node_for_childs) { nodes_count++; }
    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    uint64_t idx = 0;
    llist_for_each(node, tmp, &root->childs, node_for_childs) {
        nodes[idx++] = node;
    }
    for (uint64_t i = 0; i < idx; i++) {
        vfs_free(nodes[i]);
    }
    free(nodes);
}

int tmpfs_chmod(vfs_node_t node, uint16_t mode) {
    node->mode = mode;
    return 0;
}

int tmpfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    node->owner = uid;
    node->group = gid;
    return 0;
}

int tmpfs_delete(vfs_node_t parent, vfs_node_t node) { return 0; }

int tmpfs_rename(vfs_node_t node, const char *new) { return 0; }

void *tmpfs_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    if ((file->node->type & file_block) || (file->node->type & file_stream)) {
        return device_map(file->node->rdev, addr, offset, size, prot, flags);
    }

    tmpfs_node_t *handle = file->node->handle;
    if (!handle)
        return (void *)(int64_t)-EINVAL;

    if (offset > (size_t)handle->capability || size > SIZE_MAX - offset)
        return (void *)(int64_t)-EINVAL;

    size_t need = offset + size;
    if (need > (size_t)handle->capability) {
        if (need > MAX_TMPFS_FILE_SIZE)
            return (void *)(int64_t)-EFBIG;

        if (tmpfs_replace_content(handle, need, handle->capability, true) != 0)
            return (void *)(int64_t)-ENOMEM;
    }

    uint64_t pt_flags = PT_FLAG_U;
    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;
    if (!(pt_flags & (PT_FLAG_R | PT_FLAG_W | PT_FLAG_X)))
        pt_flags |= PT_FLAG_R;

    map_page_range(get_current_page_dir(true), (uint64_t)addr,
                   virt_to_phys((uint64_t)handle->content + offset), size,
                   pt_flags);

    return addr;
}

void tmpfs_resize(vfs_node_t node, uint64_t size) {
    tmpfs_node_t *handle = node->handle;
    if (!handle)
        return;

    if (size == 0) {
        handle->size = 0;
        if (handle->node)
            handle->node->size = 0;
        return;
    }

    size_t new_capability = size;
    if (new_capability > MAX_TMPFS_FILE_SIZE)
        return;

    if (tmpfs_replace_content(handle, new_capability, handle->size, true) != 0)
        return;
    handle->size = size;
    if (handle->node)
        handle->node->size = size;
}

int tmpfs_stat(vfs_node_t node) {
    tmpfs_node_t *tnode = node->handle;
    node->size = tnode->size;
    return 0;
}

void tmpfs_free_handle(vfs_node_t node) {
    tmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;
    if (!tnode)
        return;
    if (tnode->content && tnode->capability > 0) {
        tmpfs_mem_release(tnode->capability);
        free_frames_bytes(tnode->content, tnode->capability);
    }
    free(tnode);
}

static vfs_operations_t callbacks = {
    .open = tmpfs_open,
    .close = tmpfs_close,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .readlink = tmpfs_readlink,
    .mkdir = tmpfs_mkdir,
    .mkfile = tmpfs_mkfile,
    .symlink = tmpfs_symlink,
    .mknod = tmpfs_mknod,
    .chmod = tmpfs_chmod,
    .chown = tmpfs_chown,
    .delete = tmpfs_delete,
    .rename = tmpfs_rename,
    .stat = tmpfs_stat,
    .map = tmpfs_map,
    .mount = tmpfs_mount,
    .unmount = tmpfs_unmount,
    .resize = tmpfs_resize,

    .free_handle = tmpfs_free_handle,
};

fs_t tmpfs = {
    .name = "tmpfs",
    .magic = 0x01021994,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

void tmpfs_init() { tmpfs_fsid = vfs_regist(&tmpfs); }
