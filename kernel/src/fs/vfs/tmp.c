#include <fs/vfs/vfs.h>
#include <fs/vfs/tmp.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>

#define MAX_TMPFS_FILE_SIZE (128 * 1024 * 1024) // 128MB

int tmpfs_fsid = 0;

spinlock_t tmpfs_oplock = SPIN_INIT;

extern uint32_t device_number;

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
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        if (new_capability > MAX_TMPFS_FILE_SIZE) {
            spin_unlock(&tmpfs_oplock);
            return -EFBIG;
        }
        void *new_content = alloc_frames_bytes(new_capability);
        if (!new_content) {
            spin_unlock(&tmpfs_oplock);
            return -ENOMEM;
        }
        memcpy(new_content, handle->content, handle->capability);
        free_frames_bytes(handle->content, handle->capability);
        handle->content = new_content;
        handle->capability = new_capability;
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

    ssize_t to_copy = MIN(handle->size, size);
    memcpy(addr, handle->content, to_copy);
    return to_copy;
}

int tmpfs_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int tmpfs_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    tmpfs_node_t *handle = malloc(sizeof(tmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
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
    tmpfs_node_t *handle = malloc(sizeof(tmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
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
    tmpfs_node_t *handle = malloc(sizeof(tmpfs_node_t));
    size_t len = strlen(name) + 1;
    handle->capability = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    handle->content = alloc_frames_bytes(handle->capability);
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

    if ((flags & MAP_TYPE) == MAP_PRIVATE) {
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);
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

        void *new_content = alloc_frames_bytes(need);
        if (!new_content)
            return (void *)(int64_t)-ENOMEM;

        memcpy(new_content, handle->content, handle->capability);
        memset((uint8_t *)new_content + handle->capability, 0,
               need - handle->capability);
        free_frames_bytes(handle->content, handle->capability);
        handle->content = new_content;
        handle->capability = need;
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
    void *new_content = alloc_frames_bytes(new_capability);
    if (!new_content)
        return;

    memcpy(new_content, handle->content, MIN(new_capability, handle->size));
    if (new_capability > (size_t)handle->size) {
        memset((uint8_t *)new_content + handle->size, 0,
               new_capability - handle->size);
    }

    free_frames_bytes(handle->content, handle->capability);
    handle->content = new_content;
    handle->capability = new_capability;
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
    free_frames_bytes(tnode->content, tnode->capability);
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
