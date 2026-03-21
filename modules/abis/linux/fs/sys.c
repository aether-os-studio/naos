#include <fs/vfs/vfs.h>
#include <fs/vfs/utils.h>
#include <fs/sys.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>
#include <stdarg.h>

int sysfs_fsid = 0;

spinlock_t sysfs_oplock = SPIN_INIT;

vfs_node_t *sysfs_root = NULL;
vfs_node_t *fake_sysfs_root = NULL;

static int mount_node_old_fsid = 0;

extern uint32_t device_number;

int sysfs_mkdir(vfs_node_t *parent, const char *name, vfs_node_t *node);
int sysfs_mkfile(vfs_node_t *parent, const char *name, vfs_node_t *node);
int sysfs_symlink(vfs_node_t *parent, const char *name, vfs_node_t *node);

static const char *sysfs_relative_path(const char *path) {
    if (!path)
        return NULL;

    if (streq(path, "/sys") || streq(path, "/sys/"))
        return "";

    if (strncmp(path, "/sys/", 5) != 0)
        return NULL;

    return path + 5;
}

static vfs_node_t *sysfs_walk_dir_rel(const char *relpath, bool create) {
    if (!sysfs_root)
        return NULL;

    vfs_node_t *current = sysfs_root;
    if (!relpath || !relpath[0])
        return current;

    char *path = strdup(relpath);
    if (!path)
        return NULL;

    char *save_ptr = path;
    for (const char *component = pathtok(&save_ptr); component;
         component = pathtok(&save_ptr)) {
        if (streq(component, "."))
            continue;

        if (streq(component, "..")) {
            if (current->parent)
                current = current->parent;
            continue;
        }

        if (!(current->type & file_dir)) {
            current = NULL;
            break;
        }

        vfs_node_t *next = vfs_child_find(current, component);
        if (!next) {
            if (!create) {
                current = NULL;
                break;
            }

            next = vfs_node_alloc(current, component);
            if (!next) {
                current = NULL;
                break;
            }

            next->type = file_dir;
            int ret = sysfs_mkdir(current, component, next);
            if (ret < 0) {
                vfs_free(next);
                current = NULL;
                break;
            }
        }

        if (!(next->type & file_dir)) {
            current = NULL;
            break;
        }

        current = next;
    }

    free(path);
    return current;
}

static vfs_node_t *sysfs_resolve_parent(const char *path, char **leaf_out,
                                        bool create_dirs) {
    const char *relpath = sysfs_relative_path(path);
    if (!relpath)
        return NULL;

    char *dup = strdup(relpath);
    if (!dup)
        return NULL;

    vfs_node_t *parent = sysfs_root;
    char *leaf = dup;
    char *slash = strrchr(dup, '/');
    if (slash) {
        *slash = '\0';
        leaf = slash + 1;
        parent = sysfs_walk_dir_rel(dup, create_dirs);
    }

    if (leaf_out)
        *leaf_out = strdup(leaf);

    free(dup);

    if (leaf_out && !*leaf_out)
        return NULL;

    return parent;
}

vfs_node_t *sysfs_open_node(const char *path, uint64_t flags) {
    const char *relpath = sysfs_relative_path(path);

    if (!relpath || !sysfs_root)
        return vfs_open(path, flags);

    if (!relpath[0])
        return sysfs_root;

    return vfs_open_at(sysfs_root, relpath, flags);
}

static vfs_node_t *sysfs_mkfile_path(const char *path) {
    const char *relpath = sysfs_relative_path(path);
    if (!relpath) {
        if (vfs_mkfile(path) < 0) {
            vfs_node_t *node = vfs_open(path, 0);
            return node;
        }
        return vfs_open(path, 0);
    }

    char *leaf = NULL;
    vfs_node_t *parent = sysfs_resolve_parent(path, &leaf, true);
    if (!parent || !leaf || !leaf[0]) {
        free(leaf);
        return NULL;
    }

    vfs_node_t *node = vfs_child_find(parent, leaf);
    if (!node) {
        node = vfs_node_alloc(parent, leaf);
        if (!node) {
            free(leaf);
            return NULL;
        }

        node->type = file_none;
        int ret = sysfs_mkfile(parent, leaf, node);
        if (ret < 0) {
            vfs_free(node);
            node = NULL;
        }
    }

    free(leaf);
    return node;
}

int sysfs_symlink_path(const char *path, const char *target_path) {
    const char *relpath = sysfs_relative_path(path);
    if (!relpath)
        return vfs_symlink(path, target_path);

    char *leaf = NULL;
    vfs_node_t *parent = sysfs_resolve_parent(path, &leaf, true);
    if (!parent || !leaf || !leaf[0]) {
        free(leaf);
        return -EINVAL;
    }

    if (vfs_child_find(parent, leaf)) {
        free(leaf);
        return -EEXIST;
    }

    vfs_node_t *node = vfs_node_alloc(parent, leaf);
    if (!node) {
        free(leaf);
        return -ENOMEM;
    }

    node->type = file_symlink;
    int ret = sysfs_symlink(parent, target_path, node);
    if (ret < 0)
        vfs_free(node);

    free(leaf);
    return ret;
}

void sysfs_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {}

bool sysfs_close(vfs_node_t *node) { return false; }

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

ssize_t sysfs_readlink(vfs_node_t *node, void *addr, size_t offset,
                       size_t size) {
    sysfs_node_t *handle = node->handle;
    if (offset >= handle->size)
        return 0;

    char tmp[1024];
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, handle->content, MIN(handle->size, sizeof(tmp)));

    vfs_node_t *to_node = vfs_open_at(node->parent, (const char *)tmp, 0);
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

int sysfs_mkdir(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    node->mode = 0700;
    return 0;
}

int sysfs_mkfile(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    node->mode = 0700;
    sysfs_node_t *handle = malloc(sizeof(sysfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int sysfs_symlink(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    node->mode = 0700;
    sysfs_node_t *handle = malloc(sizeof(sysfs_node_t));
    size_t len = strlen(name) + 1;
    handle->capability = PADDING_UP(len, DEFAULT_PAGE_SIZE);
    handle->content = alloc_frames_bytes(handle->capability);
    memcpy(handle->content, name, len);
    handle->size = len;
    handle->node = node;
    node->handle = handle;
    return 0;
}

int sysfs_mount(uint64_t dev, vfs_node_t *node) {
    if (sysfs_root != fake_sysfs_root)
        return 0;
    if (sysfs_root == node)
        return 0;

    spin_lock(&sysfs_oplock);

    vfs_merge_nodes_to(node, fake_sysfs_root);

    mount_node_old_fsid = node->fsid;

    sysfs_root = node;
    node->fsid = sysfs_fsid;
    node->dev = (SYSFS_DEV_MAJOR << 8) | 0;
    node->rdev = (SYSFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&sysfs_oplock);

    return 0;
}

void sysfs_unmount(vfs_node_t *root) {
    if (root == fake_sysfs_root)
        return;

    if (root != sysfs_root)
        return;

    spin_lock(&sysfs_oplock);

    vfs_merge_nodes_to(fake_sysfs_root, root);

    root->fsid = mount_node_old_fsid;
    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    sysfs_root = fake_sysfs_root;

    root->root = root->parent ? root->parent->root : root;

    spin_unlock(&sysfs_oplock);
}

void sysfs_free_handle(vfs_node_t *node) {
    sysfs_node_t *snode = node ? node->handle : NULL;
    if (!snode)
        return;
    free_frames_bytes(snode->content, snode->capability);
    free(snode);
}

static vfs_operations_t callbacks = {
    .open = sysfs_open,
    .close = sysfs_close,
    .read = sysfs_read,
    .write = sysfs_write,
    .readlink = sysfs_readlink,
    .mkdir = sysfs_mkdir,
    .mkfile = sysfs_mkfile,
    .symlink = sysfs_symlink,
    .mount = sysfs_mount,
    .unmount = sysfs_unmount,

    .free_handle = sysfs_free_handle,
};

fs_t sysfs = {
    .name = "sysfs",
    .magic = 0x62656572,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

vfs_node_t *sysfs_ensure_dir(const char *path) {
    const char *relpath = sysfs_relative_path(path);
    if (relpath)
        return sysfs_walk_dir_rel(relpath, true);

    vfs_node_t *node = vfs_open(path, 0);
    if (node)
        return node;
    vfs_mkdir(path);
    return vfs_open(path, 0);
}

void sysfs_init() {
    sysfs_fsid = vfs_regist(&sysfs);

    fake_sysfs_root = vfs_node_alloc(rootdir, "sys");
    fake_sysfs_root->type = file_dir;
    fake_sysfs_root->fsid = sysfs_fsid;
    sysfs_root = fake_sysfs_root;

    sysfs_ensure_dir("/sys/fs/cgroup");
    sysfs_ensure_dir("/sys/fs/fuse/connections");

    sysfs_ensure_dir("/sys/kernel/debug");
    sysfs_ensure_dir("/sys/kernel/tracing");

    sysfs_ensure_dir("/sys/devices");
    sysfs_ensure_dir("/sys/devices/usb");

    sysfs_ensure_dir("/sys/module");

    sysfs_ensure_dir("/sys/dev");
    sysfs_ensure_dir("/sys/dev/char");
    sysfs_ensure_dir("/sys/dev/block");

    sysfs_ensure_dir("/sys/bus");
    sysfs_ensure_dir("/sys/bus/pci");
    sysfs_ensure_dir("/sys/bus/pci/devices");
    sysfs_ensure_dir("/sys/bus/pci/drivers");
    sysfs_ensure_dir("/sys/bus/usb");
    sysfs_ensure_dir("/sys/bus/usb/devices");
    sysfs_ensure_dir("/sys/bus/usb/drivers");

    sysfs_ensure_dir("/sys/class");
    sysfs_ensure_dir("/sys/class/graphics");
    sysfs_ensure_dir("/sys/class/input");
    sysfs_ensure_dir("/sys/class/drm");

    usb_sysfs_init();

    for (uint32_t i = 0; i < pci_device_number; i++) {
        pci_device_t *dev = pci_devices[i];
        if (dev == NULL)
            continue;

        char name[128];
        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d", dev->segment,
                dev->bus, dev->slot, dev->func);

        sysfs_ensure_dir(name);

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/class",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        char content[64];
        sprintf(content, "0x%x", dev->class_code);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/revision",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "0x%02x", dev->revision_id);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/vendor",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "0x%04x", dev->vendor_id);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/device",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "0x%04x", dev->device_id);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/subsystem_vendor",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "0x%04x", dev->subsystem_vendor_id);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/subsystem_device",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "0x%04x", dev->subsystem_device_id);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/uevent",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_mkfile_path(name);

        sprintf(content, "PCI_SLOT_NAME=%04x:%02x:%02x.%d\n", dev->segment,
                dev->bus, dev->slot, dev->func);
        vfs_write(sysfs_open_node(name, 0), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04x:%02x:%02x.%d/subsystem",
                dev->segment, dev->bus, dev->slot, dev->func);
        sysfs_symlink_path(name, "/sys/bus/pci");
    }
}

void sysfs_init_umount() {
    vfs_detach_child(sysfs_root);
    sysfs_root->parent = NULL;
}

static int next_seq_num = 1;

int alloc_seq_num() { return next_seq_num++; }

vfs_node_t *sysfs_regist_dev(char t, int major, int minor,
                             const char *real_device_path, const char *dev_name,
                             const char *other_uevent_content) {
    const char *root = (t == 'c') ? "char" : "block";

    char dev_root_path[256];
    sprintf(dev_root_path, "/sys/dev/%s/%d:%d", root, major, minor);

    bool dev_root_is_real = (strlen(real_device_path) == 0);

    vfs_node_t *real_device_node = NULL;
    if (dev_root_is_real) {
        sysfs_ensure_dir(dev_root_path);
        real_device_node = sysfs_open_node(dev_root_path, 0);
    } else {
        sysfs_ensure_dir(real_device_path);
        sysfs_symlink_path(dev_root_path, real_device_path);
        real_device_node = sysfs_open_node(real_device_path, 0);
    }

    char *fullpath = vfs_get_fullpath(real_device_node);

    char uevent_path[256];
    sprintf(uevent_path, "%s/uevent", fullpath);

    vfs_node_t *uevent_node = sysfs_mkfile_path(uevent_path);

    char uevent_content[256];
    sprintf(uevent_content, "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\nDEVPATH=%s\n%s",
            major, minor, dev_name, fullpath + 4, other_uevent_content);
    vfs_write(uevent_node, uevent_content, 0, strlen(uevent_content));

    free(fullpath);

    char buffer[256];
    sprintf(buffer, "add@/%s\nACTION=add\nSEQNUM=%d\nTAGS=:systemd:\n%s\n",
            dev_root_is_real ? dev_root_path : real_device_path,
            alloc_seq_num(), uevent_content);
    int len = strlen(buffer);
    for (int i = 0; i < len; i++) {
        if (buffer[i] == '\n')
            buffer[i] = '\0';
    }
    if (!memcmp(buffer + len - 2, "\0\0", 2))
        len--;
    netlink_kernel_uevent_send(buffer, len);

    return real_device_node;
}

vfs_node_t *sysfs_write_attr(vfs_node_t *parent, const char *name,
                             const char *content) {
    char *parent_path = vfs_get_fullpath(parent);
    char path[512];

    sprintf(path, "%s/%s", parent_path, name);
    free(parent_path);

    vfs_node_t *node = sysfs_open_node(path, 0);
    if (!node)
        node = sysfs_child_append(parent, name, false);
    if (!node)
        return NULL;

    sysfs_node_t *handle = node->handle;
    if (handle)
        handle->size = 0;
    if (content)
        vfs_write(node, content, 0, strlen(content));
    return node;
}

vfs_node_t *sysfs_write_attrf(vfs_node_t *parent, const char *name,
                              const char *fmt, ...) {
    char content[256];
    va_list ap;

    memset(content, 0, sizeof(content));
    va_start(ap, fmt);
    vsnprintf(content, sizeof(content), fmt, ap);
    va_end(ap);
    return sysfs_write_attr(parent, name, content);
}

void sysfs_detach_node(vfs_node_t *node) {
    if (!node)
        return;
    vfs_detach_child(node);
    node->parent = NULL;
}

void sysfs_detach_path(const char *path, bool nofollow) {
    vfs_node_t *node = sysfs_open_node(path, nofollow ? O_NOFOLLOW : 0);
    if (node)
        sysfs_detach_node(node);
}

vfs_node_t *sysfs_child_append(vfs_node_t *parent, const char *name,
                               bool is_dir) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    vfs_node_t *node =
        is_dir ? sysfs_ensure_dir(path) : sysfs_mkfile_path(path);

    free(parent_path);

    return node;
}

vfs_node_t *sysfs_child_append_symlink(vfs_node_t *parent, const char *name,
                                       const char *target_path) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    int ret = sysfs_symlink_path(path, target_path);

    free(parent_path);

    if (ret < 0 && ret != -EEXIST)
        return NULL;

    return sysfs_open_node(path, O_NOFOLLOW);
}
