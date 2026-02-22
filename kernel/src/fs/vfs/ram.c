#include <fs/vfs/vfs.h>
#include <fs/vfs/ram.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>

#define MAX_RAMFS_FILE_SIZE (128 * 1024 * 1024) // 128MB

int ramfs_fsid = 0;

spinlock_t ramfs_oplock = SPIN_INIT;

extern uint32_t device_number;

void ramfs_open(vfs_node_t parent, const char *name, vfs_node_t node) {}

bool ramfs_close(vfs_node_t node) { return false; }

ssize_t ramfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd->flags);
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
        return device_write(fd->node->rdev, (void *)addr, offset, size,
                            fd->flags);
    }

    spin_lock(&ramfs_oplock);
    ramfs_node_t *handle = fd->node->handle;
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        if (new_capability > MAX_RAMFS_FILE_SIZE) {
            spin_unlock(&ramfs_oplock);
            return -EFBIG;
        }
        void *new_content = alloc_frames_bytes(new_capability);
        if (!new_content) {
            spin_unlock(&ramfs_oplock);
            return -ENOMEM;
        }
        memcpy(new_content, handle->content, handle->capability);
        free_frames_bytes(handle->content, handle->capability);
        handle->content = new_content;
        handle->capability = new_capability;
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    spin_unlock(&ramfs_oplock);
    return size;
}

ssize_t ramfs_readlink(vfs_node_t node, void *addr, size_t offset,
                       size_t size) {
    ramfs_node_t *handle = node->handle;
    if (offset >= handle->size)
        return 0;

    ssize_t to_copy = MIN(handle->size, size);
    memcpy(addr, handle->content, to_copy);
    return to_copy;
}

int ramfs_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int ramfs_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    ramfs_node_t *handle = malloc(sizeof(ramfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int ramfs_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
                uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    ramfs_node_t *handle = malloc(sizeof(ramfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int ramfs_symlink(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    ramfs_node_t *handle = malloc(sizeof(ramfs_node_t));
    size_t len = strlen(name) + 1;
    handle->capability = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    handle->content = alloc_frames_bytes(handle->capability);
    memcpy(handle->content, name, len);
    handle->size = len;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int ramfs_mount(uint64_t dev, vfs_node_t node) {
    spin_lock(&ramfs_oplock);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = ramfs_fsid;
    node->dev = (RAMFS_DEV_MAJOR << 8) | 0;
    node->rdev = (RAMFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&ramfs_oplock);

    return 0;
}

void ramfs_unmount(vfs_node_t root) {
    root->fsid = (uint32_t)(root->flags >> 32);

    vfs_node_t node, ram;
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
    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    uint64_t idx = 0;
    llist_for_each(node, ram, &root->childs, node_for_childs) {
        nodes[idx++] = node;
    }
    for (uint64_t i = 0; i < idx; i++) {
        vfs_free(nodes[i]);
    }
    free(nodes);
}

int ramfs_chmod(vfs_node_t node, uint16_t mode) {
    node->mode = mode;
    return 0;
}

int ramfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    node->owner = uid;
    node->group = gid;
    return 0;
}

int ramfs_delete(vfs_node_t parent, vfs_node_t node) { return 0; }

int ramfs_rename(vfs_node_t node, const char *new) { return 0; }

void *ramfs_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

void ramfs_resize(vfs_node_t node, uint64_t size) {
    ramfs_node_t *handle = node->handle;
    size_t new_capability = size;
    void *new_content = alloc_frames_bytes(new_capability);
    memcpy(new_content, handle->content,
           MIN(new_capability, handle->capability));
    free_frames_bytes(handle->content, handle->capability);
    handle->content = new_content;
    handle->capability = new_capability;
}

int ramfs_stat(vfs_node_t node) {
    ramfs_node_t *tnode = node->handle;
    node->size = tnode->size;
    return 0;
}

void ramfs_free_handle(vfs_node_t node) {
    ramfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;
    free_frames_bytes(tnode->content, tnode->capability);
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
