#include <fs/vfs/vfs.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <fs/partition.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/pty.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>

int devtmpfs_fsid = 0;

spinlock_t devtmpfs_oplock = {0};

vfs_node_t devtmpfs_root = NULL;
vfs_node_t fake_devtmpfs_root = NULL;

static int dummy() { return 0; }

void devtmpfs_open(void *parent, const char *name, vfs_node_t node) {}

bool devtmpfs_close(void *current) { return false; }

ssize_t devtmpfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd->flags);
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
        return device_write(fd->node->rdev, (void *)addr, offset, size,
                            fd->flags);
    }

    devtmpfs_node_t *handle = fd->node->handle;
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

ssize_t devtmpfs_readlink(vfs_node_t node, void *addr, size_t offset,
                          size_t size) {
    devtmpfs_node_t *handle = node->handle;
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

int devtmpfs_mkdir(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    return 0;
}

int devtmpfs_mkfile(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->node = node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int devtmpfs_mknod(void *parent, const char *name, vfs_node_t node,
                   uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    if ((mode & S_IFMT) == S_IFBLK)
        node->type = file_block;
    if ((mode & S_IFMT) == S_IFCHR)
        node->type = file_stream;
    else
        node->type = file_none;
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->node = node;
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int devtmpfs_symlink(void *parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    int len = strlen(name);
    memcpy(handle->content, name, len);
    handle->size = len;
    handle->node = node;
    node->handle = handle;
    vfs_node_t target = vfs_open_at(node->parent, name);
    if (target) {
        node->dev = target->dev;
        node->rdev = target->rdev;
        node->type |= target->type;
    }
    return 0;
}

int devtmpfs_mount(uint64_t dev, vfs_node_t node) {
    if (devtmpfs_root != fake_devtmpfs_root)
        return -EALREADY;
    if (devtmpfs_root == node)
        return -EALREADY;

    spin_lock(&devtmpfs_oplock);

    devtmpfs_root = node;
    vfs_merge_nodes_to(devtmpfs_root, fake_devtmpfs_root);

    node->flags = (uint64_t)node->fsid << 32;
    node->fsid = devtmpfs_fsid;

    spin_unlock(&devtmpfs_oplock);

    return 0;
}

void devtmpfs_unmount(vfs_node_t root) {
    root->fsid = (uint32_t)(root->flags >> 32);
    if (root == fake_devtmpfs_root)
        return;

    if (root != devtmpfs_root)
        return;

    spin_lock(&devtmpfs_oplock);

    vfs_merge_nodes_to(fake_devtmpfs_root, root);

    root->fsid = (uint32_t)(root->flags >> 32);

    devtmpfs_root = fake_devtmpfs_root;

    spin_unlock(&devtmpfs_oplock);
}

int devtmpfs_chmod(vfs_node_t node, uint16_t mode) {
    node->mode = mode;
    return 0;
}

int devtmpfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    node->owner = uid;
    node->group = gid;
    return 0;
}

int devtmpfs_delete(void *parent, vfs_node_t node) { return 0; }

int devtmpfs_rename(void *current, const char *new) { return 0; }

int devtmpfs_ioctl(void *file, ssize_t cmd, ssize_t arg) {
    devtmpfs_node_t *tnode = file;
    if ((tnode->node->type & file_block) || (tnode->node->type & file_stream)) {
        return device_ioctl(tnode->node->rdev, cmd, (void *)arg);
    }
    return -ENOSYS;
}

void *devtmpfs_map(fd_t *file, void *addr, size_t offset, size_t size,
                   size_t prot, size_t flags) {
    if ((file->node->type & file_block) || (file->node->type & file_stream)) {
        return device_map(file->node->rdev, addr, offset, size, prot, flags);
    }
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

int devtmpfs_poll(void *file, size_t events) {
    devtmpfs_node_t *tnode = file;
    if ((tnode->node->type & file_block) || (tnode->node->type & file_stream)) {
        return device_poll(tnode->node->rdev, events);
    }
    return -ENOSYS;
}

void devtmpfs_resize(void *current, uint64_t size) {
    devtmpfs_node_t *handle = current;
    size_t new_capability = size;
    void *new_content = alloc_frames_bytes(new_capability);
    memcpy(new_content, handle->content,
           MIN(new_capability, handle->capability));
    free_frames_bytes(handle->content, handle->capability);
    handle->content = new_content;
    handle->capability = new_capability;
}

int devtmpfs_stat(void *file, vfs_node_t node) {
    devtmpfs_node_t *tnode = file;
    node->size = tnode->size;
    return 0;
}

void devtmpfs_free_handle(void *handle) {
    devtmpfs_node_t *tnode = handle;
    free_frames_bytes(tnode->content, tnode->capability);
    free(tnode);
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)devtmpfs_open,
    .close = (vfs_close_t)devtmpfs_close,
    .read = (vfs_read_t)devtmpfs_read,
    .write = (vfs_write_t)devtmpfs_write,
    .readlink = (vfs_readlink_t)devtmpfs_readlink,
    .mkdir = (vfs_mk_t)devtmpfs_mkdir,
    .mkfile = (vfs_mk_t)devtmpfs_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)devtmpfs_symlink,
    .mknod = (vfs_mknod_t)devtmpfs_mknod,
    .chmod = (vfs_chmod_t)devtmpfs_chmod,
    .chown = (vfs_chown_t)devtmpfs_chown,
    .delete = (vfs_del_t)devtmpfs_delete,
    .rename = (vfs_rename_t)devtmpfs_rename,
    .stat = (vfs_stat_t)devtmpfs_stat,
    .ioctl = (vfs_ioctl_t)devtmpfs_ioctl,
    .map = (vfs_mapfile_t)devtmpfs_map,
    .poll = (vfs_poll_t)devtmpfs_poll,
    .mount = (vfs_mount_t)devtmpfs_mount,
    .unmount = (vfs_unmount_t)devtmpfs_unmount,
    .resize = (vfs_resize_t)devtmpfs_resize,
    .dup = vfs_generic_dup,

    .free_handle = devtmpfs_free_handle,
};

fs_t devtmpfs = {
    .name = "devtmpfs",
    .magic = 0x01021994,
    .callback = &callbacks,
};

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;

    ssize_t cnt = (ssize_t)circular_int_read(&event->device_events, buf, len);

    return cnt;
}

ssize_t inputdev_event_write(void *data, const void *buf, uint64_t offset,
                             uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;

    // todo

    return len;
}

ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg) {
    dev_input_event_t *event = data;
    size_t type = _IOC_TYPE(request);
    size_t dir = _IOC_DIR(request);
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    (void)type;
    (void)dir;

    ssize_t ret = -ENOTTY;

    if (number >= 0x20 && number < (0x20 + EV_CNT)) {
        // we are in EVIOCGBIT(event: 0x20 - x) territory, beware
        return event->event_bit(data, request, (void *)arg);
    } else if (number >= 0x40 && number < (0x40 + ABS_CNT)) {
        // we are in EVIOCGABS(event: 0x40 - x) territory, beware
        return event->event_bit(data, request, (void *)arg);
    }

    if (request == 0x540b) // TCFLSH, idk why don't ask me!
        return 0;

    switch (number) {
    case 0x01: // EVIOCGVERSION idk, stolen from vmware
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
        // int toCopy = MIN(size, (size_t)strlen(event->physloc) + 1);
        // memcpy((void *)arg, event->physloc, toCopy);
        // ret = toCopy;
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
    size_t cnt = circular_int_read_poll(&e->device_events);
    if (cnt > 0 && event & EPOLLIN)
        return EPOLLIN;
    return 0;
}

void devfs_register_device(device_t *device) {
    char path[128];
    sprintf(path, "/dev/%s", device->name);

    vfs_mknod(path, 0600 | (device->type == DEV_BLOCK ? S_IFBLK : S_IFCHR),
              device->dev);

    if (device->type == DEV_BLOCK) {
        vfs_node_t device_node = vfs_open((const char *)path);
        if (!device_node)
            return;
        partition_t *part = device->ptr;

        devtmpfs_node_t *device_tnode = device_node->handle;
        device_tnode->size =
            512ULL * (part->ending_lba - part->starting_lba + 1);
        device_node->size = device_tnode->size;
    }
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

ssize_t nulldev_read(void *data, void *buf, uint64_t offset, uint64_t len,
                     uint64_t flags) {
    return 0;
}

ssize_t nulldev_write(void *data, const void *buf, uint64_t offset,
                      uint64_t len, uint64_t flags) {
    return 0;
}

ssize_t nulldev_ioctl(void *data, ssize_t request, ssize_t arg) { return 0; }

void stdio_init() {
    device_install(DEV_CHAR, DEV_NULL, NULL, "null", 0, nulldev_ioctl, NULL,
                   nulldev_read, nulldev_write, NULL);

    vfs_symlink("/dev/tty1", "/dev/tty0");

    vfs_symlink("/dev/stdin", "/dev/tty0");
    vfs_symlink("/dev/stdout", "/dev/tty0");
    vfs_symlink("/dev/stderr", "/dev/tty0");

    vfs_symlink("/dev/kmsg", "/dev/tty0");

    pty_init();
    ptmx_init();
    pts_init();
}

void circular_int_init(circular_int_t *circ, size_t size) {
    circ->read_ptr = 0;
    circ->write_ptr = 0;
    circ->buff_size = size;
    circ->buff = malloc(size);
    circ->lock_read.lock = 0;
    memset(circ->buff, 0, size);
}

size_t circular_int_read(circular_int_t *circ, uint8_t *buff, size_t length) {
    spin_lock(&circ->lock_read);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    if (write == read) {
        spin_unlock(&circ->lock_read);
        return 0;
    }

    size_t toCopy = MIN(CIRC_READABLE(write, read, circ->buff_size), length);

    for (int i = 0; i < toCopy; i++) {
        // todo: could optimize this with edge memcpy() operations
        buff[i] = circ->buff[read];
        read = (read + 1) % circ->buff_size;
    }

    circ->read_ptr = read;

    spin_unlock(&circ->lock_read);

    return toCopy;
}

size_t circular_int_write(circular_int_t *circ, const uint8_t *buff,
                          size_t length) {
    spin_lock(&circ->lock_read);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    size_t writable = CIRC_WRITABLE(write, read, circ->buff_size);
    if (length > writable) {
        spin_unlock(&circ->lock_read);
        return 0; // cannot do this
    }

    for (size_t i = 0; i < length; i++) {
        // todo: could optimize this with edge memcpy() operations
        circ->buff[write] = buff[i];
        write = (write + 1) % circ->buff_size;
    }

    circ->write_ptr = write;

    spin_unlock(&circ->lock_read);

    return length;
}

size_t circular_int_read_poll(circular_int_t *circ) {
    size_t ret = 0;
    spin_lock(&circ->lock_read);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    ret = CIRC_READABLE(write, read, circ->buff_size);
    spin_unlock(&circ->lock_read);
    return ret;
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

    circular_int_write(&item->device_events, (const void *)&event,
                       sizeof(struct input_event));
}
