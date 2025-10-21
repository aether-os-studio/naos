#include <fs/vfs/vfs.h>
#include <fs/vfs/sys.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>

int sysfs_fsid = 0;

spinlock_t sysfs_oplock = {0};

vfs_node_t sysfs_root = NULL;
vfs_node_t fake_sysfs_root = NULL;

static int mount_node_old_fsid = 0;

extern uint32_t device_number;

static int dummy() { return -ENOSYS; }

void sysfs_open(void *parent, const char *name, vfs_node_t node) {}

bool sysfs_close(void *current) { return false; }

ssize_t sysfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    sysfs_node_t *handle = fd->node->handle;
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t sysfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    sysfs_node_t *handle = fd->node->handle;
    if (offset + size > handle->capability) {
        handle->capability = offset + size;
        handle->content = realloc(handle->content, handle->capability);
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    return size;
}

ssize_t sysfs_readlink(vfs_node_t node, void *addr, size_t offset,
                       size_t size) {
    sysfs_node_t *handle = node->handle;
    if (offset >= handle->size)
        return 0;
    char tmp[1024];
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, handle->content, MIN(handle->size, sizeof(tmp)));

    vfs_node_t to_node = vfs_open_at(node->parent, (const char *)tmp);
    if (!to_node)
        return -ENOENT;

    char *from_path = vfs_get_fullpath(node);
    char *to_path = vfs_get_fullpath(to_node);

    char output[1024];
    memset(output, 0, sizeof(output));
    calculate_relative_path(output, from_path, to_path, size);
    free(from_path);
    free(to_path);

    ssize_t to_copy = MIN(size, strlen(output));
    memcpy(addr, output, to_copy);
    return to_copy;
}

int sysfs_mkdir(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int sysfs_mkfile(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    sysfs_node_t *handle = malloc(sizeof(sysfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = malloc(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int sysfs_symlink(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    sysfs_node_t *handle = malloc(sizeof(sysfs_node_t));
    size_t len = strlen(name);
    handle->capability =
        (len + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);
    handle->content = malloc(handle->capability);
    memcpy(handle->content, name, len);
    handle->size = len;
    node->handle = handle;
    return 0;
}

int sysfs_mount(vfs_node_t dev, vfs_node_t node) {
    if (sysfs_root != fake_sysfs_root)
        return -EALREADY;
    if (sysfs_root == node)
        return -EALREADY;

    spin_lock(&sysfs_oplock);

    vfs_merge_nodes_to(node, fake_sysfs_root);

    mount_node_old_fsid = node->fsid;

    sysfs_root = node;
    node->fsid = sysfs_fsid;

    spin_unlock(&sysfs_oplock);

    return 0;
}

void sysfs_unmount(vfs_node_t root) {
    if (root == fake_sysfs_root)
        return;

    if (root != sysfs_root)
        return;

    spin_lock(&sysfs_oplock);

    vfs_merge_nodes_to(fake_sysfs_root, root);

    root->fsid = mount_node_old_fsid;

    sysfs_root = fake_sysfs_root;

    spin_unlock(&sysfs_oplock);
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)sysfs_open,
    .close = (vfs_close_t)sysfs_close,
    .read = (vfs_read_t)sysfs_read,
    .write = (vfs_write_t)sysfs_write,
    .readlink = (vfs_readlink_t)sysfs_readlink,
    .mkdir = (vfs_mk_t)sysfs_mkdir,
    .mkfile = (vfs_mk_t)sysfs_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)sysfs_symlink,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)sysfs_mount,
    .unmount = (vfs_unmount_t)sysfs_unmount,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,

    .free_handle = vfs_generic_free_handle,
};

fs_t sysfs = {
    .name = "sysfs",
    .magic = 0,
    .callback = &callbacks,
};

void sysfs_init() {
    sysfs_fsid = vfs_regist(&sysfs);

    fake_sysfs_root = vfs_child_append(rootdir, "sys", NULL);
    fake_sysfs_root->type = file_dir;
    fake_sysfs_root->fsid = sysfs_fsid;
    sysfs_root = fake_sysfs_root;

    vfs_mkdir("/sys/devices");

    vfs_mkdir("/sys/dev");
    vfs_mkdir("/sys/dev/char");
    vfs_mkdir("/sys/dev/block");

    vfs_mkdir("/sys/bus");
    vfs_mkdir("/sys/bus/pci");
    vfs_mkdir("/sys/bus/pci/devices");

    vfs_mkdir("/sys/class");
    vfs_mkdir("/sys/class/graphics");
    vfs_mkdir("/sys/class/input");
    vfs_mkdir("/sys/class/drm");

    for (uint32_t i = 0; i < pci_device_number; i++) {
        pci_device_t *dev = pci_devices[i];
        if (dev == NULL)
            continue;

        char name[128];
        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d", dev->segment,
                dev->bus, dev->slot, dev->func);

        vfs_mkdir(name);

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/class",
                dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        char content[64];
        sprintf(content, "0x%x", dev->class_code);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/revision",
                dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%02x", dev->revision_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/vendor",
                dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%04x", dev->vendor_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/device",
                dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%04x", dev->device_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));
    }
}

void sysfs_init_umount() {
    list_delete(fake_sysfs_root->parent->child, fake_sysfs_root);
    fake_sysfs_root->parent = NULL;
}

static int next_seq_num = 1;

int alloc_seq_num() { return next_seq_num++; }

vfs_node_t sysfs_regist_dev(char t, int major, int minor,
                            const char *real_device_path, const char *dev_name,
                            const char *other_uevent_content) {
    const char *root = (t == 'c') ? "char" : "block";

    char dev_root_path[256];
    sprintf(dev_root_path, "/sys/dev/%s/%d:%d", root, major, minor);

    bool dev_root_is_real = (strlen(real_device_path) == 0);

    vfs_node_t real_device_node = NULL;
    if (dev_root_is_real) {
        vfs_mkdir(dev_root_path);
        real_device_node = vfs_open(dev_root_path);
    } else {
        vfs_mkdir(real_device_path);
        vfs_symlink(dev_root_path, real_device_path);
        real_device_node = vfs_open(real_device_path);
    }

    char *fullpath = vfs_get_fullpath(real_device_node);

    char uevent_path[256];
    sprintf(uevent_path, "%s/uevent", fullpath);

    vfs_mkfile(uevent_path);
    vfs_node_t uevent_node = vfs_open(uevent_path);

    char uevent_content[256];
    sprintf(uevent_content, "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\nDEVPATH=%s\n%s",
            major, minor, dev_name, fullpath + 4, other_uevent_content);
    vfs_write(uevent_node, uevent_content, 0, strlen(uevent_content));

    free(fullpath);

    char buffer[256];
    sprintf(buffer, "add@/%s\nACTION=add\nSEQNUM=%d\n%s\n",
            dev_root_is_real ? dev_root_path : real_device_path,
            alloc_seq_num(), uevent_content);
    int len = strlen(buffer);
    for (int i = 0; i < len; i++) {
        if (buffer[i] == '\n')
            buffer[i] = '\0';
    }
    netlink_kernel_uevent_send(buffer, len);

    return real_device_node;
}

vfs_node_t sysfs_child_append(vfs_node_t parent, const char *name,
                              bool is_dir) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    if (is_dir)
        vfs_mkdir(path);
    else
        vfs_mkfile(path);

    free(parent_path);

    return vfs_open(path);
}

vfs_node_t sysfs_child_append_symlink(vfs_node_t parent, const char *name,
                                      const char *target_path) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    vfs_symlink(path, target_path);

    free(parent_path);

    return vfs_open(path);
}
