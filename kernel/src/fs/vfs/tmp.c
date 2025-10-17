#include <fs/vfs/vfs.h>
#include <fs/vfs/tmp.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>

int tmpfs_fsid = 0;

spinlock_t tmpfs_oplock = {0};

extern uint32_t device_number;

static int dummy() { return 0; }

void tmpfs_open(void *parent, const char *name, vfs_node_t node) {}

bool tmpfs_close(void *current) { return false; }

ssize_t tmpfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    tmpfs_node_t *handle = fd->node->handle;
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t tmpfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    tmpfs_node_t *handle = fd->node->handle;
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        void *new_content = alloc_frames_bytes(new_capability);
        memcpy(new_content, handle->content, handle->capability);
        free_frames_bytes(handle->content, handle->capability);
        handle->content = new_content;
        handle->capability = new_capability;
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    return size;
}

ssize_t tmpfs_readlink(vfs_node_t node, void *addr, size_t offset,
                       size_t size) {
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

int tmpfs_mkdir(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int tmpfs_mkfile(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    tmpfs_node_t *handle = malloc(sizeof(tmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int tmpfs_mknod(void *parent, const char *name, vfs_node_t node, uint16_t mode,
                int dev) {
    node->dev = dev;
    node->mode = mode;
    tmpfs_node_t *handle = malloc(sizeof(tmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int tmpfs_symlink(void *parent, const char *name, vfs_node_t node) { return 0; }

int tmpfs_mount(vfs_node_t dev, vfs_node_t node) {
    spin_lock(&tmpfs_oplock);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = tmpfs_fsid;

    spin_unlock(&tmpfs_oplock);

    return 0;
}

void tmpfs_unmount(vfs_node_t root) {
    spin_lock(&tmpfs_oplock);

    root->fsid = (uint32_t)(root->flags >> 32);

    list_foreach(root->child, i) {
        vfs_node_t node = i->data;
        vfs_free(node);
        list_delete(root->child, node);
    }

    spin_unlock(&tmpfs_oplock);
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

int tmpfs_delete(void *parent, vfs_node_t node) { return 0; }

int tmpfs_rename(void *current, const char *new) { return 0; }

void *tmpfs_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    return general_map((vfs_read_t)tmpfs_read, file, (uint64_t)addr, size, prot,
                       flags, offset);
}

void tmpfs_resize(void *current, uint64_t size) {
    tmpfs_node_t *handle = current;
    size_t new_capability = size;
    void *new_content = alloc_frames_bytes(new_capability);
    memcpy(new_content, handle->content,
           MIN(new_capability, handle->capability));
    free_frames_bytes(handle->content, handle->capability);
    handle->content = new_content;
    handle->capability = new_capability;
}

int tmpfs_stat(void *file, vfs_node_t node) {
    tmpfs_node_t *tnode = file;
    node->size = tnode->size;
    return 0;
}

void tmpfs_free_handle(void *handle) {
    tmpfs_node_t *tnode = handle;
    free_frames_bytes(tnode->content, tnode->capability);
    free(tnode);
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)tmpfs_open,
    .close = (vfs_close_t)tmpfs_close,
    .read = (vfs_read_t)tmpfs_read,
    .write = (vfs_write_t)tmpfs_write,
    .readlink = (vfs_readlink_t)tmpfs_readlink,
    .mkdir = (vfs_mk_t)tmpfs_mkdir,
    .mkfile = (vfs_mk_t)tmpfs_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)tmpfs_symlink,
    .mknod = (vfs_mknod_t)tmpfs_mknod,
    .chmod = (vfs_chmod_t)tmpfs_chmod,
    .chown = (vfs_chown_t)tmpfs_chown,
    .delete = (vfs_del_t)tmpfs_delete,
    .rename = (vfs_rename_t)tmpfs_rename,
    .stat = (vfs_stat_t)tmpfs_stat,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)tmpfs_map,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)tmpfs_mount,
    .unmount = (vfs_unmount_t)tmpfs_unmount,
    .resize = (vfs_resize_t)tmpfs_resize,
    .dup = vfs_generic_dup,

    .free_handle = tmpfs_free_handle,
};

fs_t tmpfs = {
    .name = "tmpfs",
    .magic = 0x01021994,
    .callback = &callbacks,
};

void tmpfs_init() { tmpfs_fsid = vfs_regist(&tmpfs); }
