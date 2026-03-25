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

DEFINE_LLIST(sysfs_bin_attributes);

typedef struct sysfs_bin_attribute_bucket {
    struct llist_header node;
    bus_device_t *device;
    bin_attribute_t *attr;
} sysfs_bin_attribute_bucket_t;

void sysfs_register_bin_attr(bus_device_t *device, bin_attribute_t *bin_attr) {
    sysfs_bin_attribute_bucket_t *bucket =
        calloc(1, sizeof(sysfs_bin_attribute_bucket_t));
    llist_init_head(&bucket->node);
    bucket->device = device;
    bucket->attr = bin_attr;

    llist_append(&sysfs_bin_attributes, &bucket->node);
}

int sysfs_mkdir(vfs_node_t *parent, const char *name, vfs_node_t *node);
int sysfs_mkfile(vfs_node_t *parent, const char *name, vfs_node_t *node);
int sysfs_symlink(vfs_node_t *parent, const char *name, vfs_node_t *node);

void sysfs_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {}

bool sysfs_close(vfs_node_t *node) { return false; }

ssize_t sysfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    sysfs_node_t *handle = fd->node->handle;
    char *fullpath = vfs_get_fullpath(handle->node);
    sysfs_bin_attribute_bucket_t *ptr, *tmp;
    llist_for_each(ptr, tmp, &sysfs_bin_attributes, node) {
        bool matched = false;
        if (ptr->device->sysfs_path &&
            strstr(fullpath, ptr->device->sysfs_path) == fullpath) {
            matched = strstr(fullpath + strlen(ptr->device->sysfs_path),
                             ptr->attr->name) != NULL;
        }
        if (!matched && ptr->device->bus_link_path &&
            strstr(fullpath, ptr->device->bus_link_path) == fullpath) {
            matched = strstr(fullpath + strlen(ptr->device->bus_link_path),
                             ptr->attr->name) != NULL;
        }
        if (matched) {
            free(fullpath);
            return ptr->attr->read(ptr->device, ptr->attr, addr, offset, size);
        }
    }
    free(fullpath);
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t sysfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    sysfs_node_t *handle = fd->node->handle;
    char *fullpath = vfs_get_fullpath(handle->node);
    sysfs_bin_attribute_bucket_t *ptr, *tmp;
    llist_for_each(ptr, tmp, &sysfs_bin_attributes, node) {
        bool matched = false;
        if (ptr->device->sysfs_path &&
            strstr(fullpath, ptr->device->sysfs_path) == fullpath) {
            matched = strstr(fullpath + strlen(ptr->device->sysfs_path),
                             ptr->attr->name) != NULL;
        }
        if (!matched && ptr->device->bus_link_path &&
            strstr(fullpath, ptr->device->bus_link_path) == fullpath) {
            matched = strstr(fullpath + strlen(ptr->device->bus_link_path),
                             ptr->attr->name) != NULL;
        }
        if (matched) {
            free(fullpath);
            return ptr->attr->write(ptr->device, ptr->attr, addr, offset, size);
        }
    }
    free(fullpath);
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

    ssize_t to_copy = MIN(size - offset, strlen(output));
    memcpy(addr, output + offset, to_copy);

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
        return -ENXIO;
    if (sysfs_root == node)
        return -ENXIO;

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

vfs_node_t *sysfs_ensure_symlink_at(vfs_node_t *start, const char *path,
                                    const char *target) {
    vfs_node_t *node = vfs_open_at(start, path, 0);
    if (node)
        return node;
    vfs_symlink_at(start, path, target);
    return vfs_open_at(start, path, 0);
}

vfs_node_t *sysfs_ensure_symlink(const char *path, const char *target) {
    return sysfs_ensure_symlink_at(rootdir, path, target);
}

vfs_node_t *sysfs_ensure_file_at(vfs_node_t *start, const char *path) {
    vfs_node_t *node = vfs_open_at(start, path, 0);
    if (node)
        return node;
    vfs_mkfile_at(start, path);
    return vfs_open_at(start, path, 0);
}

vfs_node_t *sysfs_ensure_file(const char *path) {
    return sysfs_ensure_file_at(rootdir, path);
}

vfs_node_t *sysfs_ensure_dir_at(vfs_node_t *start, const char *path) {
    vfs_node_t *node = vfs_open_at(start, path, 0);
    if (node)
        return node;
    vfs_mkdir_at(start, path);
    return vfs_open_at(start, path, 0);
}

vfs_node_t *sysfs_ensure_dir(const char *path) {
    return sysfs_ensure_dir_at(rootdir, path);
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
}

void sysfs_register_device(bus_device_t *device) {
    if (!device->bus)
        return;

    char bus_root[128];
    snprintf(bus_root, sizeof(bus_root), "/sys/bus/%s", device->bus->name);
    sysfs_ensure_dir(bus_root);
    vfs_node_t *devices_root = sysfs_ensure_dir(device->bus->devices_path);
    sysfs_ensure_dir(device->bus->drivers_path);

    const char *devpath = NULL;
    for (int i = 0; i < device->attrs_count; i++) {
        attribute_t *attr = device->attrs[i];
        if (!strcmp(attr->name, "DEVPATH")) {
            devpath = attr->value;
            break;
        }
    }

    char name[128];
    device->get_device_path(device, name, sizeof(name));
    char real_path[256];
    if (devpath && devpath[0]) {
        snprintf(real_path, sizeof(real_path), "/sys%s", devpath);
    } else {
        snprintf(real_path, sizeof(real_path), "%s/%s",
                 device->bus->devices_path, name);
    }

    free(device->sysfs_path);
    device->sysfs_path = strdup(real_path);

    char link_path[256];
    snprintf(link_path, sizeof(link_path), "%s/%s", device->bus->devices_path,
             name);
    free(device->bus_link_path);
    device->bus_link_path = strdup(link_path);

    vfs_node_t *device_root = sysfs_ensure_dir(real_path);
    sysfs_ensure_symlink(link_path, real_path);

    sysfs_ensure_symlink_at(device_root, "subsystem", bus_root);

    for (int i = 0; i < device->bin_attrs_count; i++) {
        bin_attribute_t *bin_attr = device->bin_attrs[i];
        sysfs_ensure_file_at(device_root, bin_attr->name);
        sysfs_register_bin_attr(device, bin_attr);
    }

    vfs_node_t *uevent_node = sysfs_ensure_file_at(device_root, "uevent");
    uint64_t offset = 0;
    for (int i = 0; i < device->attrs_count; i++) {
        attribute_t *attr = device->attrs[i];
        if (strcmp(attr->name, "DEVPATH") != 0) {
            vfs_node_t *attr_node =
                sysfs_ensure_file_at(device_root, attr->name);
            if (attr_node) {
                char attr_content[256];
                int attr_len = snprintf(attr_content, sizeof(attr_content),
                                        "%s\n", attr->value ? attr->value : "");
                vfs_write(attr_node, attr_content, 0, attr_len);
            }
        }

        char content[128];
        int len = snprintf(content, sizeof(content), "%s=%s\n", attr->name,
                           attr->value);
        offset += vfs_write(uevent_node, content, offset, len);
    }
}

void sysfs_unregister_device(bus_device_t *device) {}

void sysfs_init_umount() {
    vfs_detach_child(sysfs_root);
    sysfs_root->parent = NULL;
}

static int next_seq_num = 1;

int alloc_seq_num() { return next_seq_num++; }

vfs_node_t *sysfs_regist_dev(char t, int major, int minor,
                             const char *real_device_path, const char *dev_name,
                             const char *other_uevent_content,
                             const char *subsystem_path, const char *class_path,
                             const char *class_name,
                             const char *parent_device_path) {
    const char *root = (t == 'c') ? "char" : "block";

    char dev_root_path[256];
    sprintf(dev_root_path, "/sys/dev/%s/%d:%d", root, major, minor);

    bool dev_root_is_real = (strlen(real_device_path) == 0);

    vfs_node_t *real_device_node = NULL;
    if (dev_root_is_real) {
        sysfs_ensure_dir(dev_root_path);
        real_device_node = vfs_open(dev_root_path, 0);
    } else {
        sysfs_ensure_dir(real_device_path);
        sysfs_ensure_symlink(dev_root_path, real_device_path);
        real_device_node = vfs_open(real_device_path, 0);
    }

    char *fullpath = vfs_get_fullpath(real_device_node);

    char dev_path[256];
    sprintf(dev_path, "%s/dev", fullpath);
    vfs_mkfile(dev_path);
    vfs_node_t *dev_node = vfs_open(dev_path, 0);
    if (dev_node) {
        char dev_content[32];
        int dev_len =
            snprintf(dev_content, sizeof(dev_content), "%d:%d\n", major, minor);
        vfs_write(dev_node, dev_content, 0, dev_len);
    }

    if (subsystem_path && subsystem_path[0]) {
        char subsystem_link[256];
        sprintf(subsystem_link, "%s/subsystem", fullpath);
        sysfs_ensure_symlink(subsystem_link, subsystem_path);
    }

    if (class_path && class_path[0] && class_name && class_name[0]) {
        char class_link[256];
        sprintf(class_link, "%s/%s", class_path, class_name);
        sysfs_ensure_symlink(class_link, fullpath);
    }

    if (!dev_root_is_real) {
        const char *last_slash = strrchr(fullpath, '/');
        if (last_slash && last_slash != fullpath) {
            char parent_path[256];
            size_t parent_len = (size_t)(last_slash - fullpath);
            memcpy(parent_path, fullpath, parent_len);
            parent_path[parent_len] = '\0';

            char child_device_link[256];
            sprintf(child_device_link, "%s/device", fullpath);
            sysfs_ensure_symlink(child_device_link, parent_path);

            if (parent_device_path && parent_device_path[0]) {
                char parent_device_link[256];
                sprintf(parent_device_link, "%s/device", parent_path);
                sysfs_ensure_symlink(parent_device_link, parent_device_path);
            }
        }
    }

    char devpath_for_event[256];
    snprintf(devpath_for_event, sizeof(devpath_for_event), "%s", fullpath + 4);

    char uevent_path[256];
    sprintf(uevent_path, "%s/uevent", fullpath);

    vfs_mkfile(uevent_path);
    vfs_node_t *uevent_node = vfs_open(uevent_path, 0);
    ASSERT(uevent_node);

    const char *extra = other_uevent_content ? other_uevent_content : "";
    size_t uevent_content_len =
        snprintf(NULL, 0, "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\nDEVPATH=%s\n%s",
                 major, minor, dev_name, devpath_for_event, extra) +
        1;
    char *uevent_content = malloc(uevent_content_len);
    snprintf(uevent_content, uevent_content_len,
             "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\nDEVPATH=%s\n%s", major, minor,
             dev_name, devpath_for_event, extra);
    vfs_write(uevent_node, uevent_content, 0, strlen(uevent_content));

    free(fullpath);

    int seqnum = alloc_seq_num();
    size_t buffer_len =
        snprintf(NULL, 0, "add@%s\nACTION=add\nSEQNUM=%d\nTAGS=:systemd:\n%s\n",
                 devpath_for_event, seqnum, uevent_content) +
        1;
    char *buffer = malloc(buffer_len);
    snprintf(buffer, buffer_len,
             "add@%s\nACTION=add\nSEQNUM=%d\nTAGS=:systemd:\n%s\n",
             devpath_for_event, seqnum, uevent_content);
    size_t src_len = strlen(buffer);
    size_t dst_len = 0;
    bool last_was_nul = false;
    for (size_t i = 0; i < src_len; i++) {
        char c = buffer[i];
        if (c == '\n')
            c = '\0';
        if (c == '\0') {
            if (last_was_nul)
                continue;
            last_was_nul = true;
        } else {
            last_was_nul = false;
        }
        buffer[dst_len++] = c;
    }
    if (dst_len == 0 || buffer[dst_len - 1] != '\0')
        buffer[dst_len++] = '\0';
    netlink_kernel_uevent_send(buffer, (int)dst_len);
    free(buffer);
    free(uevent_content);

    return real_device_node;
}

vfs_node_t *sysfs_child_append(vfs_node_t *parent, const char *name,
                               bool is_dir) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    vfs_node_t *node =
        is_dir ? sysfs_ensure_dir(path) : sysfs_ensure_file(path);

    free(parent_path);

    return node;
}

vfs_node_t *sysfs_child_append_symlink(vfs_node_t *parent, const char *name,
                                       const char *target_path) {
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    vfs_node_t *node = sysfs_ensure_symlink(path, target_path);

    free(parent_path);

    return node;
}
