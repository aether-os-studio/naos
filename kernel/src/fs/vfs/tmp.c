#include <fs/vfs/tmp.h>

int tmpfs_fsid = 0;

int tmp_mount(vfs_node_t dev, vfs_node_t node) {
    node->fsid = tmpfs_fsid;
    node->handle = malloc(sizeof(struct tmpfs_node));
    tmpfs_node_t handle = node->handle;
    handle->name = strdup(node->name);
    handle->size = 1;
    handle->content = alloc_frames_bytes(handle->size);
    handle->size = 0;
    handle->dev = 0;
    handle->rdev = 0;
    handle->type = file_dir;
    handle->mode = node->mode;
    handle->parent = NULL;
    handle->lock.lock = 0;

    return 0;
}

void tmp_unmount(vfs_node_t root) {}

void tmp_open(void *parent, const char *name, vfs_node_t node) {
    node->handle = malloc(sizeof(struct tmpfs_node));
    tmpfs_node_t handle = node->handle;
    handle->name = strdup(node->name);
    handle->size = 1;
    handle->content = alloc_frames_bytes(handle->size);
    handle->size = 0;
    handle->dev = node->dev;
    handle->rdev = node->rdev;
    handle->type = node->type;
    handle->mode = node->mode;
    handle->parent = NULL;
    handle->lock.lock = 0;
}

bool tmp_close(void *current) { return true; }

ssize_t tmp_write(fd_t *fd, const void *addr, size_t offset, size_t len) {
    void *data = fd->node->handle;

    tmpfs_node_t ctx = data;
    if (offset + len > ctx->size) {
        size_t new_size = ctx->size * 2;
        void *new_data = alloc_frames_bytes(new_size);
        if (!new_data)
            return -ENOMEM;
        memcpy(new_data, ctx->content, ctx->size);
        free_frames_bytes(ctx->content, ctx->size);
        ctx->content = new_data;
        ctx->size = new_size;
    }
    memcpy(ctx->content + offset, addr, len);
    fd->node->size = ctx->size;
    return len;
}

ssize_t tmp_read(fd_t *fd, void *addr, size_t offset, size_t len) {
    void *data = fd->node->handle;

    tmpfs_node_t ctx = data;
    size_t avail = ctx->size - offset;
    if (avail <= 0)
        return 0;
    size_t copy_len = len < avail ? len : avail;
    memcpy(addr, ctx->content + offset, copy_len);
    return copy_len;
}

ssize_t tmp_readlink(vfs_node_t node, void *addr, size_t offset, size_t len) {
    void *data = node->handle;

    tmpfs_node_t ctx = data;
    size_t avail = ctx->size - offset;
    if (avail <= 0)
        return 0;
    size_t copy_len = len < avail ? len : avail;
    memcpy(addr, ctx->content + offset, copy_len);
    return copy_len;
}

int tmp_link(void *parent, const char *name, vfs_node_t node) {
    return -ENOSYS;
}

int tmp_symlink(void *parent, const char *to, vfs_node_t node) {
    node->handle = malloc(sizeof(struct tmpfs_node));
    tmpfs_node_t handle = node->handle;
    handle->name = strdup(node->name);
    uint64_t len = strlen(to);
    handle->content = alloc_frames_bytes(len);
    handle->size = len;
    strcpy(handle->content, to);
    handle->dev = node->dev;
    handle->rdev = node->rdev;
    handle->type = file_symlink;
    handle->mode = node->mode;
    handle->parent = NULL;
    handle->lock.lock = 0;

    return 0;
}

int tmp_mkfile(void *parent, const char *name, vfs_node_t node) {
    node->handle = malloc(sizeof(struct tmpfs_node));
    tmpfs_node_t handle = node->handle;
    handle->name = strdup(name);
    handle->size = 1;
    handle->content = alloc_frames_bytes(handle->size);
    handle->size = 0;
    handle->dev = node->dev;
    handle->rdev = node->rdev;
    handle->type = file_none;
    handle->mode = node->mode;
    handle->parent = NULL;
    handle->lock.lock = 0;

    return 0;
}

int tmp_mkdir(void *parent, const char *name, vfs_node_t node) {
    node->handle = malloc(sizeof(struct tmpfs_node));
    tmpfs_node_t handle = node->handle;
    handle->name = strdup(name);
    handle->dev = node->dev;
    handle->rdev = node->rdev;
    handle->type = file_dir;
    handle->mode = node->mode;
    handle->parent = NULL;
    handle->lock.lock = 0;

    return 0;
}

int tmp_mknod(void *parent, const char *name, vfs_node_t node, uint16_t mode,
              int dev) {
    return -ENOSYS;
}

int tmp_chmod(vfs_node_t node, uint16_t mode) {
    tmpfs_node_t handle = node->handle;
    handle->mode = mode;
    node->mode = handle->mode;

    return 0;
}

int tmp_delete(void *parent, vfs_node_t node) {
    tmpfs_node_t handle = node->handle;
    free_frames_bytes(handle->content, handle->size);
    free(handle->name);
    free(handle);
    return 0;
}

int tmp_rename(void *current, const char *new) { return -ENOSYS; }

int tmp_stat(void *file, vfs_node_t node) {
    tmpfs_node_t current_handle = file;
    node->size = current_handle->size;
    return 0;
}

int tmp_ioctl(void *file, ssize_t cmd, ssize_t arg) { return -ENOSYS; }

int tmp_poll(void *file, size_t events) { return -ENOSYS; }

void tmp_resize(void *current, uint64_t size) {
    if (size == 0)
        return;

    tmpfs_node_t ctx = current;

    spin_lock(&ctx->lock);
    void *new_data = alloc_frames_bytes(size);
    memcpy(new_data, ctx->content, MIN(size, ctx->size));
    free_frames_bytes(ctx->content, ctx->size);
    ctx->content = new_data;
    ctx->size = size;
    spin_unlock(&ctx->lock);
}

void *tmp_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
              size_t flags) {
    tmpfs_node_t ctx = file->node->handle;

    map_page_range(
        get_current_page_dir(true), (uint64_t)addr,
        translate_address(get_current_page_dir(false), (uint64_t)ctx->content),
        size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

static struct vfs_callback callbacks = {
    .mount = tmp_mount,
    .unmount = tmp_unmount,
    .open = tmp_open,
    .close = (vfs_close_t)tmp_close,
    .read = (vfs_read_t)tmp_read,
    .write = (vfs_write_t)tmp_write,
    .readlink = (vfs_readlink_t)tmp_readlink,
    .mkdir = tmp_mkdir,
    .mkfile = tmp_mkfile,
    .link = tmp_link,
    .symlink = tmp_symlink,
    .mknod = tmp_mknod,
    .chmod = tmp_chmod,
    .delete = (vfs_del_t)tmp_delete,
    .rename = (vfs_rename_t)tmp_rename,
    .map = (vfs_mapfile_t)tmp_map,
    .stat = tmp_stat,
    .ioctl = tmp_ioctl,
    .poll = tmp_poll,
    .resize = (vfs_resize_t)tmp_resize,
    .dup = vfs_generic_dup,
};

fs_t tmpfs = {
    .name = "tmpfs",
    .magic = 0,
    .callback = &callbacks,
};

void tmpfs_init() { tmpfs_fsid = vfs_regist(&tmpfs); }
