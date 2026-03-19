#include <fs/vfs/vfs.h>
#include <fs/dev.h>
#include <fs/sys.h>
#include <fs/partition.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/tty.h>
#include <dev/pty.h>
#include <net/netlink.h>
#include <boot/boot.h>
#include <arch/arch.h>
#include <fs/vfs/tmpfs_limit.h>

int devtmpfs_fsid = 0;

spinlock_t devtmpfs_oplock = SPIN_INIT;

vfs_node_t *devtmpfs_root = NULL;
vfs_node_t *fake_devtmpfs_root = NULL;

static int devtmpfs_replace_content(devtmpfs_node_t *handle,
                                    size_t new_capability, size_t preserve_size,
                                    bool zero_tail) {
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

static void devtmpfs_sync_node_from_handle(vfs_node_t *node,
                                           devtmpfs_node_t *handle) {
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

static void devtmpfs_init_handle_from_node(devtmpfs_node_t *handle,
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

static devtmpfs_node_t *devtmpfs_alloc_handle(vfs_node_t *node,
                                              size_t capability) {
    devtmpfs_node_t *handle = calloc(1, sizeof(devtmpfs_node_t));
    if (!handle)
        return NULL;

    devtmpfs_init_handle_from_node(handle, node);
    handle->capability = capability;

    if (capability > 0) {
        if (devtmpfs_replace_content(handle, capability, 0, true) != 0) {
            free(handle);
            return NULL;
        }
    }

    devtmpfs_sync_node_from_handle(node, handle);
    return handle;
}

void devtmpfs_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;

    if (node && node->handle)
        devtmpfs_sync_node_from_handle(node, node->handle);

    if ((node->type & file_block) || (node->type & file_stream)) {
        device_open(node->rdev, NULL);
    }
}

bool devtmpfs_close(vfs_node_t *node) {
    if (!node)
        return false;
    if ((node->type & file_block) || (node->type & file_stream))
        device_close(node->rdev);
    return false;
}

#define MAX_DEVTMPFS_FILE_SIZE (128 * 1024 * 1024) // 128MB

ssize_t devtmpfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd);
    }

    devtmpfs_node_t *handle = fd->node->handle;
    if (offset >= handle->size)
        return 0;
    ssize_t to_copy = MIN(handle->size - offset, size);
    memcpy(addr, handle->content + offset, to_copy);
    return to_copy;
}

ssize_t devtmpfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_write(fd->node->rdev, (void *)addr, offset, size, fd);
    }

    devtmpfs_node_t *handle = fd->node->handle;
    if (offset > SIZE_MAX - size)
        return -EFBIG;
    if (offset + size > handle->capability) {
        size_t new_capability = offset + size;
        if (new_capability > MAX_DEVTMPFS_FILE_SIZE) {
            return -EFBIG;
        }
        if (devtmpfs_replace_content(handle, new_capability, handle->capability,
                                     false) != 0) {
            return -ENOMEM;
        }
    }
    memcpy(handle->content + offset, addr, size);
    handle->size = MAX(handle->size, offset + size);
    devtmpfs_sync_node_from_handle(fd->node, handle);
    return size;
}

ssize_t devtmpfs_readlink(vfs_node_t *node, void *addr, size_t offset,
                          size_t size) {
    devtmpfs_node_t *handle = node->handle;
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

int devtmpfs_mkdir(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;
    node->mode = 0700;
    devtmpfs_node_t *handle = devtmpfs_alloc_handle(node, 0);
    if (!handle)
        return -ENOMEM;
    node->handle = handle;
    return 0;
}

int devtmpfs_mkfile(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    (void)name;
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = devtmpfs_alloc_handle(node, DEFAULT_PAGE_SIZE);
    if (!handle)
        return -ENOMEM;
    node->handle = handle;
    return 0;
}

int devtmpfs_mknod(vfs_node_t *parent, const char *name, vfs_node_t *node,
                   uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = devtmpfs_alloc_handle(node, DEFAULT_PAGE_SIZE);
    if (!handle)
        return -ENOMEM;
    node->handle = handle;
    return 0;
}

int devtmpfs_symlink(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    (void)parent;
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = devtmpfs_alloc_handle(node, DEFAULT_PAGE_SIZE);
    if (!handle)
        return -ENOMEM;
    int len = strlen(name);
    memcpy(handle->content, name, len);
    handle->size = len;
    node->handle = handle;
    vfs_node_t *target = vfs_open_at(node->parent, name, 0);
    if (target) {
        handle->dev = target->dev;
        handle->rdev = target->rdev;
        handle->type = node->type | target->type;
    }
    devtmpfs_sync_node_from_handle(node, handle);
    return 0;
}

static int devtmpfs_link_target(vfs_node_t *parent, vfs_node_t *target,
                                vfs_node_t *node) {
    if (!parent || !target || !node)
        return -EINVAL;

    if (target->root != parent->root)
        return -EXDEV;
    if (target->type & file_dir)
        return -EPERM;

    devtmpfs_node_t *handle = target->handle;
    if (!handle)
        return -ENOENT;

    spin_lock(&devtmpfs_oplock);
    handle->link_count++;
    handle->handle_refs++;
    node->handle = handle;
    devtmpfs_sync_node_from_handle(node, handle);
    spin_unlock(&devtmpfs_oplock);

    return 0;
}

static int devtmpfs_link_existing(vfs_node_t *parent, vfs_node_t *target,
                                  vfs_node_t *node) {
    return devtmpfs_link_target(parent, target, node);
}

int devtmpfs_link(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    if (!parent || !name || !node)
        return -EINVAL;

    vfs_node_t *target = vfs_open(name, O_NOFOLLOW);
    if (!target)
        return -ENOENT;
    return devtmpfs_link_target(parent, target, node);
}

int devtmpfs_mount(uint64_t dev, vfs_node_t *node) {
    if (devtmpfs_root != fake_devtmpfs_root)
        return 0;
    if (devtmpfs_root == node)
        return 0;

    spin_lock(&devtmpfs_oplock);

    devtmpfs_root = node;
    vfs_merge_nodes_to(devtmpfs_root, fake_devtmpfs_root);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = devtmpfs_fsid;
    node->dev = (DEVFS_DEV_MAJOR << 8) | 0;
    node->rdev = (DEVFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&devtmpfs_oplock);

    return 0;
}

void devtmpfs_unmount(vfs_node_t *root) {
    if (root == fake_devtmpfs_root)
        return;

    if (root != devtmpfs_root)
        return;

    spin_lock(&devtmpfs_oplock);

    vfs_merge_nodes_to(fake_devtmpfs_root, root);

    root->fsid = (uint32_t)(root->flags >> 32);
    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    devtmpfs_root = fake_devtmpfs_root;

    spin_unlock(&devtmpfs_oplock);
}

int devtmpfs_chmod(vfs_node_t *node, uint16_t mode) {
    devtmpfs_node_t *handle = node ? node->handle : NULL;
    if (handle) {
        handle->mode = mode;
        devtmpfs_sync_node_from_handle(node, handle);
    } else if (node) {
        node->mode = mode;
    }
    return 0;
}

int devtmpfs_chown(vfs_node_t *node, uint64_t uid, uint64_t gid) {
    devtmpfs_node_t *handle = node ? node->handle : NULL;
    if (handle) {
        handle->owner = (uint32_t)uid;
        handle->group = (uint32_t)gid;
        devtmpfs_sync_node_from_handle(node, handle);
    } else if (node) {
        node->owner = (uint32_t)uid;
        node->group = (uint32_t)gid;
    }
    return 0;
}

int devtmpfs_delete(vfs_node_t *parent, vfs_node_t *node) {
    (void)parent;

    devtmpfs_node_t *handle = node ? node->handle : NULL;
    if (!handle)
        return 0;

    spin_lock(&devtmpfs_oplock);
    if (handle->link_count)
        handle->link_count--;
    spin_unlock(&devtmpfs_oplock);

    return 0;
}

int devtmpfs_rename(vfs_node_t *node, const char *new) { return 0; }

int devtmpfs_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    if (!fd->node || !fd->node->handle)
        return -EBADF;
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_ioctl(fd->node->rdev, cmd, (void *)arg, fd);
    }
    return -ENOSYS;
}

void *devtmpfs_map(fd_t *file, void *addr, size_t offset, size_t size,
                   size_t prot, size_t flags) {
    if ((file->node->type & file_block) || (file->node->type & file_stream)) {
        return device_map(file->node->rdev, addr, offset, size, prot, file);
    }

    devtmpfs_node_t *handle = file->node->handle;
    if (!handle)
        return (void *)(int64_t)-EINVAL;

    if (offset > (size_t)handle->capability || size > SIZE_MAX - offset)
        return (void *)(int64_t)-EINVAL;

    size_t need = offset + size;
    if (need > (size_t)handle->capability) {
        if (need > MAX_DEVTMPFS_FILE_SIZE)
            return (void *)(int64_t)-EFBIG;

        if (devtmpfs_replace_content(handle, need, handle->capability, true) !=
            0)
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

    map_page_range(get_current_page_dir(true), (uint64_t)addr,
                   virt_to_phys((uint64_t)handle->content + offset), size,
                   pt_flags);

    return addr;
}

int devtmpfs_poll(vfs_node_t *node, size_t events) {
    if (!node || !node->handle)
        return EPOLLNVAL;
    if ((node->type & file_block) || (node->type & file_stream)) {
        return device_poll(node->rdev, events);
    }
    return -ENOSYS;
}

void devtmpfs_resize(vfs_node_t *node, uint64_t size) {
    devtmpfs_node_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;

    spin_lock(&devtmpfs_oplock);
    if (size == 0) {
        handle->size = 0;
        devtmpfs_sync_node_from_handle(node, handle);
        spin_unlock(&devtmpfs_oplock);
        return;
    }

    size_t new_capability = size;
    if (new_capability > MAX_DEVTMPFS_FILE_SIZE) {
        spin_unlock(&devtmpfs_oplock);
        return;
    }

    if (devtmpfs_replace_content(handle, new_capability, handle->size, true) !=
        0) {
        spin_unlock(&devtmpfs_oplock);
        return;
    }
    handle->size = size;
    devtmpfs_sync_node_from_handle(node, handle);
    spin_unlock(&devtmpfs_oplock);
}

int devtmpfs_stat(vfs_node_t *node) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode) {
        if (node) {
            node->size = 0;
            node->realsize = 0;
        }
        return 0;
    }
    devtmpfs_sync_node_from_handle(node, tnode);
    return 0;
}

void devtmpfs_free_handle(vfs_node_t *node) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;

    void *content = NULL;
    size_t capability = 0;
    bool free_handle = false;

    spin_lock(&devtmpfs_oplock);
    if (tnode->handle_refs)
        tnode->handle_refs--;
    if (!tnode->handle_refs) {
        content = tnode->content;
        capability = tnode->capability;
        tnode->content = NULL;
        tnode->capability = 0;
        free_handle = true;
    }
    spin_unlock(&devtmpfs_oplock);

    if (!free_handle)
        return;

    if (content && capability > 0) {
        tmpfs_mem_release(capability);
        free_frames_bytes(content, capability);
    }
    free(tnode);
}

static vfs_operations_t callbacks = {
    .open = devtmpfs_open,
    .close = devtmpfs_close,
    .read = devtmpfs_read,
    .write = devtmpfs_write,
    .readlink = devtmpfs_readlink,
    .mkdir = devtmpfs_mkdir,
    .mkfile = devtmpfs_mkfile,
    .link = devtmpfs_link,
    .link_node = devtmpfs_link_existing,
    .symlink = devtmpfs_symlink,
    .mknod = devtmpfs_mknod,
    .chmod = devtmpfs_chmod,
    .chown = devtmpfs_chown,
    .delete = devtmpfs_delete,
    .rename = devtmpfs_rename,
    .stat = devtmpfs_stat,
    .ioctl = devtmpfs_ioctl,
    .map = devtmpfs_map,
    .poll = devtmpfs_poll,
    .mount = devtmpfs_mount,
    .unmount = devtmpfs_unmount,
    .resize = devtmpfs_resize,

    .free_handle = devtmpfs_free_handle,
};

fs_t devtmpfs = {
    .name = "devtmpfs",
    .magic = 0x01021994,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_ALWAYS_OPEN,
};

ssize_t inputdev_open(void *data, void *arg) {
    dev_input_event_t *event = data;
    event->timesOpened++;
    return 0;
}

ssize_t inputdev_close(void *data, void *arg) {
    dev_input_event_t *event = data;
    if (event->timesOpened > 0)
        event->timesOpened--;
    return 0;
}

static int inputdev_wait_node(vfs_node_t *node, uint32_t events,
                              const char *reason) {
    if (!node || !current_task)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    int polled = vfs_poll(node, want);
    if (polled < 0)
        return polled;
    if (polled & (int)want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(node, &wait) < 0)
        return -EINVAL;

    polled = vfs_poll(node, want);
    if (polled < 0) {
        vfs_poll_wait_disarm(&wait);
        return polled;
    }
    if (polled & (int)want) {
        vfs_poll_wait_disarm(&wait);
        return EOK;
    }

    int ret = vfs_poll_wait_sleep(node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
}

static bool input_event_queue_push(dev_input_event_t *event,
                                   const struct input_event *in) {
    if (!event || !in || !event->event_queue || !event->event_queue_capacity) {
        return false;
    }

    spin_lock(&event->event_queue_lock);

    if (event->event_queue_count >= event->event_queue_capacity) {
        event->event_queue_head =
            (event->event_queue_head + 1) % event->event_queue_capacity;
        event->event_queue_count--;
        event->event_queue_overflow = true;
    }

    event->event_queue[event->event_queue_tail] = *in;
    event->event_queue_tail =
        (event->event_queue_tail + 1) % event->event_queue_capacity;
    event->event_queue_count++;

    spin_unlock(&event->event_queue_lock);
    return true;
}

static size_t input_event_queue_pop(dev_input_event_t *event,
                                    struct input_event *out,
                                    size_t max_events) {
    if (!event || !out || max_events == 0) {
        return 0;
    }

    size_t produced = 0;
    spin_lock(&event->event_queue_lock);

    if (event->event_queue_overflow && produced < max_events) {
        memset(&out[produced], 0, sizeof(struct input_event));
        uint64_t now_ns = nano_time();
        out[produced].sec = now_ns / 1000000000ULL;
        out[produced].usec = (now_ns % 1000000000ULL) / 1000ULL;
        out[produced].type = EV_SYN;
        out[produced].code = 3; // SYN_DROPPED
        out[produced].value = 0;
        event->event_queue_overflow = false;
        produced++;
    }

    while (produced < max_events && event->event_queue_count > 0 &&
           event->event_queue_capacity > 0) {
        out[produced++] = event->event_queue[event->event_queue_head];
        event->event_queue_head =
            (event->event_queue_head + 1) % event->event_queue_capacity;
        event->event_queue_count--;
    }

    spin_unlock(&event->event_queue_lock);
    return produced;
}

static bool input_event_queue_has_data(dev_input_event_t *event) {
    if (!event) {
        return false;
    }

    bool has_data = false;
    spin_lock(&event->event_queue_lock);
    has_data = (event->event_queue_count > 0) || event->event_queue_overflow;
    spin_unlock(&event->event_queue_lock);
    return has_data;
}

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;
    if (!event || !buf)
        return -EINVAL;
    if (len == 0)
        return 0;
    if (len < sizeof(struct input_event))
        return -EINVAL;

    len = (len / sizeof(struct input_event)) * sizeof(struct input_event);
    struct input_event *events = (struct input_event *)buf;
    size_t max_events = len / sizeof(struct input_event);

    while (true) {
        size_t cnt = input_event_queue_pop(event, events, max_events);
        if (cnt > 0)
            return cnt * sizeof(struct input_event);
        if (flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        // int reason = inputdev_wait_node(event->devnode, EPOLLIN,
        // "evdev_read"); if (reason != EOK)
        //     return -EINTR;

        return 0;
    }
}

ssize_t inputdev_event_write(void *data, const void *buf, uint64_t offset,
                             uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;

    // todo

    return len;
}

ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg, fd_t *fd) {
    dev_input_event_t *event = data;
    size_t type = _IOC_TYPE(request);
    size_t dir = _IOC_DIR(request);
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    (void)type;
    (void)dir;

    ssize_t ret = -ENOTTY;

    if (number >= 0x20 && number < (0x20 + EV_CNT)) {
        return event->event_bit(data, request, (void *)arg);
    } else if (number >= 0x40 && number < (0x40 + ABS_CNT)) {
        return event->event_bit(data, request, (void *)arg);
    }

    if (request == 0x540b)
        return 0;

    switch (number) {
    case 0x01:
        *((int *)arg) = 0x10001;
        ret = 0;
        break;
    case 0x02: // EVIOCGID
        memcpy((void *)arg, &event->inputid, sizeof(struct input_id));
        ret = 0;
        break;
    case 0x06: { // EVIOCGNAME(len)
        int toCopy = MIN(size, (size_t)strlen(event->devname) + 1);
        memcpy((void *)arg, event->devname, toCopy);
        ret = toCopy;
        break;
    }
    case 0x07: { // EVIOCGPHYS(len)
        ret = 0;
        break;
    }
    case 0x08: // EVIOCGUNIQ()
        if (event->uniq[0]) {
            int toCopy = MIN(size, (size_t)strlen(event->uniq) + 1);
            memcpy((void *)arg, event->uniq, toCopy);
            ret = toCopy;
        } else {
            ret = -ENODATA;
        }
        break;
    case 0x09: // EVIOCGPROP()
        int toCopy = MIN(sizeof(size_t), size);
        memcpy((void *)arg, &event->properties, toCopy);
        ret = size;
        break;
    case 0x03: // EVIOCGREP
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x18: // EVIOCGKEY()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x19: // EVIOCGLED()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x1b: // EVIOCGSW()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0xa0: // EVIOCSCLOCKID()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x91:
        ret = 0;
        break;
    default:
        printk("inputdev_ioctl(): Unsupported ioctl: %#018lx\n", request);
        ret = -ENOTTY;
        break;
    }

    return ret;
}

ssize_t inputdev_poll(void *data, size_t event) {
    dev_input_event_t *e = data;
    if (input_event_queue_has_data(e) && (event & EPOLLIN))
        return EPOLLIN;
    return 0;
}

void devfs_register_device(device_t *device) {
    char path[128];
    sprintf(path, "/dev/%s", device->name);

    vfs_mknod(path, 0600 | (device->type == DEV_BLOCK ? S_IFBLK : S_IFCHR),
              device->dev);

    if (device->type == DEV_BLOCK) {
        vfs_node_t *device_node = vfs_open((const char *)path, 0);
        if (!device_node)
            return;
        partition_t *part = device->ptr;

        devtmpfs_node_t *device_tnode = device_node->handle;
        device_tnode->size =
            512ULL * (part->ending_lba - part->starting_lba + 1);
        device_node->size = device_tnode->size;
    }
}

void devfs_unregister_device(device_t *device) {
    if (!device || !device->name[0])
        return;

    char path[128];
    sprintf(path, "/dev/%s", device->name);

    vfs_node_t *node = vfs_open(path, O_NOFOLLOW);
    if (!node)
        node = vfs_open(path, 0);
    if (!node)
        return;

    vfs_free(node);
}

bool devfs_initialized = false;

void devtmpfs_init() {
    devtmpfs_fsid = vfs_regist(&devtmpfs);

    fake_devtmpfs_root = vfs_child_append(rootdir, "dev", NULL);
    fake_devtmpfs_root->mode = 0600;
    fake_devtmpfs_root->type = file_dir;
    fake_devtmpfs_root->fsid = devtmpfs_fsid;
    devtmpfs_root = fake_devtmpfs_root;

    devfs_initialized = true;
}

void devtmpfs_init_umount() {
    vfs_detach_child(devtmpfs_root);
    devtmpfs_root->parent = NULL;
}

ssize_t nulldev_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    return 0;
}

ssize_t nulldev_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    serial_printk(buf, len);
    return len;
}

static uint64_t simple_rand() {
    uint32_t seed = boot_get_boottime() * 100 + nano_time() / 10;
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return ((uint64_t)seed << 32) | seed;
}

ssize_t zerodev_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    memset(buf, 0, len);
    return len;
}

ssize_t zerodev_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    return 0;
}

ssize_t urandom_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    for (uint64_t i = 0; i < len; i++) {
        uint64_t rand = simple_rand();
        uint8_t byte = (rand >> 5) & 0xFF;
        if (copy_to_user((char *)buf + i, &byte, 1))
            return -EFAULT;
    }
    return len;
}

ssize_t urandom_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    return 0;
}

extern char *default_console;

void setup_console_symlinks() {
    vfs_node_t *tty_node = vfs_open(default_console, 0);
    if (!tty_node)
        return;

    vfs_mknod("/dev/console", 0600 | S_IFCHR, tty_node->rdev);

    vfs_mknod("/dev/tty", 0600 | S_IFCHR, tty_node->rdev);
    if (vfs_open("/dev/tty0", 0) == NULL)
        vfs_mknod("/dev/tty0", 0600 | S_IFCHR, tty_node->rdev);
    vfs_mknod("/dev/tty1", 0600 | S_IFCHR, tty_node->rdev);

    vfs_mknod("/dev/stdin", 0600 | S_IFCHR, tty_node->rdev);
    vfs_mknod("/dev/stdout", 0600 | S_IFCHR, tty_node->rdev);
    vfs_mknod("/dev/stderr", 0600 | S_IFCHR, tty_node->rdev);

    vfs_mknod("/dev/kmsg", 0600 | S_IFCHR, tty_node->rdev);
}

void devfs_nodes_init() {
    vfs_mkdir("/dev/shm");
    vfs_mkdir("/dev/bus");
    vfs_mkdir("/dev/bus/usb");

    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "null", 0, NULL, NULL, NULL,
                   NULL, nulldev_read, nulldev_write, NULL);
    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "zero", 0, NULL, NULL, NULL,
                   NULL, zerodev_read, zerodev_write, NULL);
    device_install(DEV_CHAR, DEV_SYSDEV, NULL, "urandom", 0, NULL, NULL, NULL,
                   NULL, urandom_read, urandom_write, NULL);

    setup_console_symlinks();

    pty_init();
    ptmx_init();
    pts_init();
}

void input_generate_event(dev_input_event_t *item, uint16_t type, uint16_t code,
                          int32_t value, uint64_t sec, uint64_t usecs) {
    if (!item || item->timesOpened == 0)
        return;

    struct input_event event;
    memset(&event, 0, sizeof(struct input_event));
    event.sec = sec;
    event.usec = usecs;
    event.type = type;
    event.code = code;
    event.value = value;

    bool queued = input_event_queue_push(item, &event);
    if (queued && item->devnode) {
        vfs_poll_notify(item->devnode, EPOLLIN);
    }
}
