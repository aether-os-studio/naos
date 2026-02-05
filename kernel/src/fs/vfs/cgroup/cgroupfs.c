#include <fs/vfs/cgroup/cgroupfs.h>

static int cgroupfs_fsid = 0;

spinlock_t cgroupfs_oplock = SPIN_INIT;

vfs_node_t cgroupfs_root = NULL;
vfs_node_t fake_cgroupfs_root = NULL;

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

int cgroupfs_mkdir(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    cgroupfs_node_t *handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = node;
    handle->size = 0;
    node->handle = handle;

    vfs_node_t procs_node = vfs_child_append(node, "cgroup.procs", NULL);
    procs_node->mode = 0600;
    procs_node->type = file_none;
    handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = procs_node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    procs_node->handle = handle;

    vfs_node_t controllers_node =
        vfs_child_append(node, "cgroup.controllers", NULL);
    controllers_node->mode = 0600;
    controllers_node->type = file_none;
    handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = controllers_node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    controllers_node->handle = handle;

    return 0;
}

int cgroupfs_mkfile(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    cgroupfs_node_t *handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

ssize_t cgroupfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    return 0;
}

ssize_t cgroupfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    return size;
}

int cgroupfs_delete(void *parent, vfs_node_t node) { return 0; }

void cgroupfs_free_handle(void *handle) {
    cgroupfs_node_t *tnode = handle;
    free_frames_bytes(tnode->content, tnode->capability);
    free(tnode);
}

static int dummy() { return 0; }

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)cgroupfs_read,
    .write = (vfs_write_t)cgroupfs_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)cgroupfs_mkdir,
    .mkfile = (vfs_mk_t)cgroupfs_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)cgroupfs_delete,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)cgroupfs_mount,
    .unmount = (vfs_unmount_t)cgroupfs_unmount,
    .remount = (vfs_remount_t)dummy,
    .resize = (vfs_resize_t)dummy,

    .free_handle = cgroupfs_free_handle,
};

fs_t cgroup2fs = {
    .name = "cgroup2",
    .magic = 0x63677270,
    .callback = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

void cgroupfs_init() {
    cgroupfs_fsid = vfs_regist(&cgroup2fs);

    fake_cgroupfs_root = vfs_node_alloc(NULL, "cgroupfs_root");
    fake_cgroupfs_root->mode = 0600;
    fake_cgroupfs_root->type = file_dir;
    fake_cgroupfs_root->fsid = cgroupfs_fsid;
    cgroupfs_root = fake_cgroupfs_root;

    vfs_node_t procs_node =
        vfs_child_append(cgroupfs_root, "cgroup.procs", NULL);
    procs_node->mode = 0600;
    procs_node->type = file_none;
    cgroupfs_node_t *handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = procs_node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    procs_node->handle = handle;

    vfs_node_t controllers_node =
        vfs_child_append(cgroupfs_root, "cgroup.controllers", NULL);
    controllers_node->mode = 0600;
    controllers_node->type = file_none;
    handle = malloc(sizeof(cgroupfs_node_t));
    handle->node = controllers_node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    controllers_node->handle = handle;
}
