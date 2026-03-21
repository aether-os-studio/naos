#include <fs/vfs/vfs.h>
#include <fs/ram.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>
#include <fs/vfs/tmpfs_limit.h>

#define MAX_RAMFS_FILE_SIZE (128 * 1024 * 1024) // 128MB

int ramfs_fsid = 0;

spinlock_t ramfs_oplock = SPIN_INIT;

extern uint32_t device_number;

static int ramfs_replace_content(ramfs_node_t *handle, size_t new_capability,
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

static void ramfs_sync_node_from_handle(vfs_node_t *node,
                                        ramfs_node_t *handle) {
    if (!node || !handle)
        return;

    node->inode = handle->inode;
    node->dev = handle->dev;
    node->rdev = handle->rdev;
    node->blksz = handle->blksz;
    node->owner = handle->owner;
    node->group = handle->group;
    node->type = handle->type;
    node->mode = handle->mode;
    node->size = handle->size;
    node->realsize = handle->capability;
}

static void ramfs_init_handle_from_node(ramfs_node_t *handle,
                                        vfs_node_t *node) {
    if (!handle || !node)
        return;

    handle->inode = node->inode;
    handle->dev = node->dev;
    handle->rdev = node->rdev;
    handle->blksz = node->blksz;
    handle->owner = node->owner;
    handle->group = node->group;
    handle->type = node->type;
    handle->mode = node->mode;
    handle->link_count = 1;
    handle->handle_refs = 1;
}

static ramfs_node_t *ramfs_alloc_handle(vfs_node_t *node, size_t capability) {
    ramfs_node_t *handle = calloc(1, sizeof(ramfs_node_t));
    if (!handle)
        return NULL;

    ramfs_init_handle_from_node(handle, node);
    handle->capability = capability;

    if (capability > 0) {
        if (ramfs_replace_content(handle, capability, 0, true) != 0) {
            free(handle);
            return NULL;
        }
    }

    ramfs_sync_node_from_handle(node, handle);
    return handle;
}

void ramfs_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;

    if (node && node->handle)
        ramfs_sync_node_from_handle(node, node->handle);
}

bool ramfs_close(vfs_node_t *node) { return false; }

ssize_t ramfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd);
    }

    ramfs_node_t *handle = fd->node->handle;
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t ramfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_write(fd->node->rdev, (void *)addr, offset, size, fd);
    }

    spin_lock(&ramfs_oplock);
    ramfs_node_t *handle = fd->node->handle;
    if (offset > SIZE_MAX - size) {
        spin_unlock(&ramfs_oplock);
        return -EFBIG;
    }
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        if (new_capability > MAX_RAMFS_FILE_SIZE) {
            spin_unlock(&ramfs_oplock);
            return -EFBIG;
        }
        if (ramfs_replace_content(handle, new_capability, handle->capability,
                                  false) != 0) {
            spin_unlock(&ramfs_oplock);
            return -ENOMEM;
        }
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    ramfs_sync_node_from_handle(fd->node, handle);
    spin_unlock(&ramfs_oplock);
    return size;
}

ssize_t ramfs_readlink(vfs_node_t *node, void *addr, size_t offset,
                       size_t size) {
    ramfs_node_t *handle = node->handle;
    if (offset >= handle->size)
        return 0;

    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

int ramfs_mkdir(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;
    node->mode = 0700;
    return 0;
}

int ramfs_mkfile(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;
    node->mode = 0700;
    ramfs_node_t *handle = ramfs_alloc_handle(node, DEFAULT_PAGE_SIZE);
    if (!handle)
        return -ENOMEM;
    node->handle = handle;
    return 0;
}

int ramfs_mknod(vfs_node_t *parent, const char *name, vfs_node_t *node,
                uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    ramfs_node_t *handle = ramfs_alloc_handle(node, DEFAULT_PAGE_SIZE);
    if (!handle)
        return -ENOMEM;
    node->handle = handle;
    return 0;
}

int ramfs_symlink(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    size_t len = strlen(name);
    ramfs_node_t *handle =
        ramfs_alloc_handle(node, PADDING_UP(len, DEFAULT_PAGE_SIZE));
    if (!handle)
        return -ENOMEM;
    memcpy(handle->content, name, len);
    handle->size = len;
    node->handle = handle;
    ramfs_sync_node_from_handle(node, handle);
    return 0;
}

static int ramfs_link_target(vfs_node_t *parent, vfs_node_t *target,
                             vfs_node_t *node) {
    if (!parent || !target || !node)
        return -EINVAL;

    if (target->root != parent->root)
        return -EXDEV;
    if (target->type & file_dir)
        return -EPERM;

    ramfs_node_t *handle = target->handle;
    if (!handle)
        return -ENOENT;

    spin_lock(&ramfs_oplock);
    handle->link_count++;
    handle->handle_refs++;
    node->handle = handle;
    ramfs_sync_node_from_handle(node, handle);
    spin_unlock(&ramfs_oplock);

    return 0;
}

static int ramfs_link_existing(vfs_node_t *parent, vfs_node_t *target,
                               vfs_node_t *node) {
    return ramfs_link_target(parent, target, node);
}

int ramfs_link(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    if (!parent || !name || !node)
        return -EINVAL;

    vfs_node_t *target = vfs_open(name, O_NOFOLLOW);
    if (!target)
        return -ENOENT;
    return ramfs_link_target(parent, target, node);
}

int ramfs_mount(uint64_t dev, vfs_node_t *node) {
    spin_lock(&ramfs_oplock);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = ramfs_fsid;
    node->dev = (RAMFS_DEV_MAJOR << 8) | 0;
    node->rdev = (RAMFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&ramfs_oplock);

    return 0;
}

void ramfs_unmount(vfs_node_t *root) {
    root->fsid = (uint32_t)(root->flags >> 32);

    vfs_node_t *node, *ram;
    llist_for_each(node, ram, &root->childs, node_for_childs) {
        if (node == node->root) {
            char *node_path = vfs_get_fullpath(node);
            vfs_unmount((const char *)node_path);
            free(node_path);
        }
    }

    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    uint64_t nodes_count = 0;
    llist_for_each(node, ram, &root->childs, node_for_childs) { nodes_count++; }
    vfs_node_t **nodes = calloc(nodes_count, sizeof(vfs_node_t *));
    uint64_t idx = 0;
    llist_for_each(node, ram, &root->childs, node_for_childs) {
        nodes[idx++] = node;
    }
    for (uint64_t i = 0; i < idx; i++) {
        vfs_free(nodes[i]);
    }
    free(nodes);
}

int ramfs_chmod(vfs_node_t *node, uint16_t mode) {
    ramfs_node_t *handle = node ? node->handle : NULL;
    if (handle) {
        handle->mode = mode;
        ramfs_sync_node_from_handle(node, handle);
    } else if (node) {
        node->mode = mode;
    }
    return 0;
}

int ramfs_chown(vfs_node_t *node, uint64_t uid, uint64_t gid) {
    ramfs_node_t *handle = node ? node->handle : NULL;
    if (handle) {
        handle->owner = (uint32_t)uid;
        handle->group = (uint32_t)gid;
        ramfs_sync_node_from_handle(node, handle);
    } else if (node) {
        node->owner = (uint32_t)uid;
        node->group = (uint32_t)gid;
    }
    return 0;
}

int ramfs_delete(vfs_node_t *parent, vfs_node_t *node) {
    (void)parent;

    ramfs_node_t *handle = node ? node->handle : NULL;
    if (!handle)
        return 0;

    spin_lock(&ramfs_oplock);
    if (handle->link_count)
        handle->link_count--;
    spin_unlock(&ramfs_oplock);

    return 0;
}

int ramfs_rename(vfs_node_t *node, const char *new) { return 0; }

void *ramfs_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    if ((flags & MAP_TYPE) == MAP_PRIVATE) {
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);
    }

    ramfs_node_t *handle = file->node->handle;
    if (!handle)
        return (void *)(int64_t)-EINVAL;

    if (offset > (size_t)handle->capability || size > SIZE_MAX - offset)
        return (void *)(int64_t)-EINVAL;

    size_t need = offset + size;
    if (need > (size_t)handle->capability) {
        if (need > MAX_RAMFS_FILE_SIZE)
            return (void *)(int64_t)-EFBIG;

        if (ramfs_replace_content(handle, need, handle->capability, true) != 0)
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

    map_page_range((uint64_t *)phys_to_virt(current_task->mm->page_table_addr),
                   (uint64_t)addr,
                   virt_to_phys((uint64_t)handle->content + offset), size,
                   pt_flags);

    return addr;
}

void ramfs_resize(vfs_node_t *node, uint64_t size) {
    ramfs_node_t *handle = node->handle;
    if (!handle)
        return;

    spin_lock(&ramfs_oplock);
    size_t new_capability = size;
    if (new_capability > MAX_RAMFS_FILE_SIZE) {
        spin_unlock(&ramfs_oplock);
        return;
    }

    if (ramfs_replace_content(handle, new_capability, handle->capability,
                              false) != 0) {
        spin_unlock(&ramfs_oplock);
        return;
    }

    handle->size = MIN(handle->size, size);
    ramfs_sync_node_from_handle(node, handle);
    spin_unlock(&ramfs_oplock);
}

int ramfs_stat(vfs_node_t *node) {
    ramfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode) {
        if (node) {
            node->size = 0;
            node->realsize = 0;
        }
        return 0;
    }
    ramfs_sync_node_from_handle(node, tnode);
    return 0;
}

void ramfs_free_handle(vfs_node_t *node) {
    ramfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;

    void *content = NULL;
    size_t capability = 0;
    bool free_handle = false;

    spin_lock(&ramfs_oplock);
    if (tnode->handle_refs)
        tnode->handle_refs--;
    if (!tnode->handle_refs) {
        content = tnode->content;
        capability = tnode->capability;
        tnode->content = NULL;
        tnode->capability = 0;
        free_handle = true;
    }
    spin_unlock(&ramfs_oplock);

    if (!free_handle)
        return;

    if (content && capability > 0) {
        tmpfs_mem_release(capability);
        free_frames_bytes(content, capability);
    }
    free(tnode);
}

static vfs_operations_t callbacks = {
    .open = ramfs_open,
    .close = ramfs_close,
    .read = ramfs_read,
    .write = ramfs_write,
    .readlink = ramfs_readlink,
    .mkdir = ramfs_mkdir,
    .mkfile = ramfs_mkfile,
    .link = ramfs_link,
    .link_node = ramfs_link_existing,
    .symlink = ramfs_symlink,
    .mknod = ramfs_mknod,
    .chmod = ramfs_chmod,
    .chown = ramfs_chown,
    .delete = ramfs_delete,
    .rename = ramfs_rename,
    .stat = ramfs_stat,
    .map = ramfs_map,
    .mount = ramfs_mount,
    .unmount = ramfs_unmount,
    .resize = ramfs_resize,

    .free_handle = ramfs_free_handle,
};

fs_t ramfs = {
    .name = "ramfs",
    .magic = 0x858458f6,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

void ramfs_init() { ramfs_fsid = vfs_regist(&ramfs); }
