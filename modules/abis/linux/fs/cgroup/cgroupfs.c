#include <fs/cgroup/cgroupfs.h>

static int cgroupfs_fsid = 0;

spinlock_t cgroupfs_oplock = SPIN_INIT;

vfs_node_t cgroupfs_root = NULL;
vfs_node_t fake_cgroupfs_root = NULL;

static int cgroupfs_resize_handle(cgroupfs_node_t *handle, size_t need) {
    if (!handle)
        return -EINVAL;
    if (need <= (size_t)handle->capability)
        return 0;

    void *new_content = alloc_frames_bytes(need);
    if (!new_content)
        return -ENOMEM;

    if (handle->content && handle->capability > 0) {
        memcpy(new_content, handle->content, handle->capability);
        free_frames_bytes(handle->content, handle->capability);
    }

    handle->content = new_content;
    handle->capability = need;
    return 0;
}

static int cgroupfs_write_string(cgroupfs_node_t *handle, const char *content) {
    size_t len = content ? strlen(content) : 0;
    size_t need = MAX((size_t)DEFAULT_PAGE_SIZE, len + 1);

    int ret = cgroupfs_resize_handle(handle, need);
    if (ret < 0)
        return ret;

    if (len > 0)
        memcpy(handle->content, content, len);
    if (handle->content)
        handle->content[len] = '\0';
    handle->size = (int)len;
    if (handle->node)
        handle->node->size = len;
    return 0;
}

static cgroupfs_node_t *cgroupfs_alloc_handle(vfs_node_t node) {
    cgroupfs_node_t *handle = calloc(1, sizeof(cgroupfs_node_t));
    if (!handle)
        return NULL;

    handle->node = node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    if (!handle->content) {
        free(handle);
        return NULL;
    }

    node->handle = handle;
    return handle;
}

static int cgroupfs_init_file(vfs_node_t parent, const char *name,
                              uint16_t mode, const char *content) {
    vfs_node_t node = vfs_child_append(parent, name, NULL);
    node->mode = mode;
    node->type = file_none;

    cgroupfs_node_t *handle = cgroupfs_alloc_handle(node);
    if (!handle)
        return -ENOMEM;

    return cgroupfs_write_string(handle, content ? content : "");
}

static int cgroupfs_init_dir(vfs_node_t node) {
    node->mode = 0755;
    cgroupfs_node_t *handle = cgroupfs_alloc_handle(node);
    if (!handle)
        return -ENOMEM;

    if (cgroupfs_init_file(node, "cgroup.procs", 0644, "") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.threads", 0644, "") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.controllers", 0644,
                           "cpu io memory pids\n") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.events", 0644,
                           "populated 1\nfrozen 0\n") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.type", 0644, "domain\n") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.freeze", 0644, "0\n") < 0)
        return -ENOMEM;
    if (cgroupfs_init_file(node, "cgroup.subtree_control", 0644, "\n") < 0)
        return -ENOMEM;

    return 0;
}

int cgroupfs_mount(uint64_t dev, vfs_node_t node) {
    if (cgroupfs_root != fake_cgroupfs_root)
        return 0;
    if (cgroupfs_root == node)
        return 0;

    spin_lock(&cgroupfs_oplock);

    cgroupfs_root = node;
    vfs_merge_nodes_to(cgroupfs_root, fake_cgroupfs_root);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = cgroupfs_fsid;
    node->dev = (CGROUPFS_DEV_MAJOR << 8) | 0;
    node->rdev = (CGROUPFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&cgroupfs_oplock);

    return 0;
}

void cgroupfs_unmount(vfs_node_t root) {
    if (root == fake_cgroupfs_root)
        return;

    if (root != cgroupfs_root)
        return;

    spin_lock(&cgroupfs_oplock);

    vfs_merge_nodes_to(fake_cgroupfs_root, root);

    root->fsid = (uint32_t)(root->flags >> 32);
    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    cgroupfs_root = fake_cgroupfs_root;

    spin_unlock(&cgroupfs_oplock);
}

int cgroupfs_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    return cgroupfs_init_dir(node);
}

int cgroupfs_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0644;
    if (node->handle)
        return -EEXIST;

    cgroupfs_node_t *handle = cgroupfs_alloc_handle(node);
    if (!handle)
        return -ENOMEM;

    return 0;
}

ssize_t cgroupfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    cgroupfs_node_t *handle = fd->node->handle;
    if (!handle || offset >= (size_t)handle->size)
        return 0;

    ssize_t to_copy = MIN((size_t)handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t cgroupfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    cgroupfs_node_t *handle = fd->node->handle;
    if (!handle)
        return -EINVAL;

    if (offset + size + 1 > (size_t)handle->capability) {
        int ret = cgroupfs_resize_handle(
            handle, PADDING_UP(offset + size + 1, DEFAULT_PAGE_SIZE));
        if (ret < 0)
            return ret;
    }

    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, (int)(offset + size));
    handle->content[handle->size] = '\0';
    fd->node->size = handle->size;
    return size;
}

int cgroupfs_delete(vfs_node_t parent, vfs_node_t node) { return 0; }

void cgroupfs_free_handle(vfs_node_t node) {
    cgroupfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;
    free_frames_bytes(tnode->content, tnode->capability);
    free(tnode);
}

static vfs_operations_t callbacks = {
    .read = cgroupfs_read,
    .write = cgroupfs_write,
    .mkdir = cgroupfs_mkdir,
    .mkfile = cgroupfs_mkfile,
    .delete = cgroupfs_delete,
    .mount = cgroupfs_mount,
    .unmount = cgroupfs_unmount,

    .free_handle = cgroupfs_free_handle,
};

fs_t cgroup2fs = {
    .name = "cgroup2",
    .magic = 0x63677270,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

void cgroupfs_init() {
    cgroupfs_fsid = vfs_regist(&cgroup2fs);

    fake_cgroupfs_root = vfs_node_alloc(NULL, "cgroupfs_root");
    fake_cgroupfs_root->mode = 0755;
    fake_cgroupfs_root->type = file_dir;
    fake_cgroupfs_root->fsid = cgroupfs_fsid;
    cgroupfs_root = fake_cgroupfs_root;
    cgroupfs_init_dir(cgroupfs_root);
}
