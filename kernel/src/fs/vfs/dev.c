#include <fs/vfs/vfs.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <fs/partition.h>
#include <dev/device.h>
#include <drivers/kernel_logger.h>
#include <drivers/tty.h>
#include <drivers/pty.h>
#include <net/netlink.h>
#include <mm/mm_syscall.h>
#include <boot/boot.h>

int devtmpfs_fsid = 0;

spinlock_t devtmpfs_oplock = SPIN_INIT;

vfs_node_t devtmpfs_root = NULL;
vfs_node_t fake_devtmpfs_root = NULL;

void devtmpfs_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    if ((node->type & file_block) || (node->type & file_stream)) {
        device_open(node->rdev, NULL);
    }
}

bool devtmpfs_close(vfs_node_t node) {
    devtmpfs_node_t *dnode = node ? node->handle : NULL;
    if (!dnode)
        return false;
    if ((dnode->node->type & file_block) || (dnode->node->type & file_stream)) {
        device_close(dnode->node->rdev);
    }
    return false;
}

#define MAX_DEVTMPFS_FILE_SIZE (128 * 1024 * 1024) // 128MB

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
        if (new_capability > MAX_DEVTMPFS_FILE_SIZE) {
            return -EFBIG;
        }
        void *new_content = alloc_frames_bytes(new_capability);
        if (!new_content) {
            return -ENOMEM;
        }
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

    vfs_node_t to_node = vfs_open_at(node->parent, (const char *)tmp, 0);
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

int devtmpfs_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->node = node;
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int devtmpfs_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->node = node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int devtmpfs_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
                   uint16_t mode, int dev) {
    node->dev = dev;
    node->rdev = dev;
    node->mode = mode & 0777;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->node = node;
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    handle->size = 0;
    node->handle = handle;
    return 0;
}

int devtmpfs_symlink(vfs_node_t parent, const char *name, vfs_node_t node) {
    node->mode = 0700;
    if (node->handle) {
        return -EEXIST;
    }
    devtmpfs_node_t *handle = malloc(sizeof(devtmpfs_node_t));
    handle->capability = DEFAULT_PAGE_SIZE;
    handle->content = alloc_frames_bytes(handle->capability);
    int len = strlen(name);
    memcpy(handle->content, name, len);
    handle->size = len;
    handle->node = node;
    node->handle = handle;
    vfs_node_t target = vfs_open_at(node->parent, name, 0);
    if (target) {
        node->dev = target->dev;
        node->rdev = target->rdev;
        node->type |= target->type;
    }
    return 0;
}

int devtmpfs_mount(uint64_t dev, vfs_node_t node) {
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

void devtmpfs_unmount(vfs_node_t root) {
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

int devtmpfs_chmod(vfs_node_t node, uint16_t mode) {
    node->mode = mode;
    return 0;
}

int devtmpfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    node->owner = uid;
    node->group = gid;
    return 0;
}

int devtmpfs_delete(vfs_node_t parent, vfs_node_t node) { return 0; }

int devtmpfs_rename(vfs_node_t node, const char *new) { return 0; }

int devtmpfs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return -EBADF;
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

    devtmpfs_node_t *handle = file->node->handle;
    if (!handle)
        return (void *)(int64_t)-EINVAL;

    if (offset > (size_t)handle->capability || size > SIZE_MAX - offset)
        return (void *)(int64_t)-EINVAL;

    size_t need = offset + size;
    if (need > (size_t)handle->capability) {
        if (need > MAX_DEVTMPFS_FILE_SIZE)
            return (void *)(int64_t)-EFBIG;

        void *new_content = alloc_frames_bytes(need);
        if (!new_content)
            return (void *)(int64_t)-ENOMEM;

        memcpy(new_content, handle->content, handle->capability);
        memset((uint8_t *)new_content + handle->capability, 0,
               need - handle->capability);
        free_frames_bytes(handle->content, handle->capability);
        handle->content = new_content;
        handle->capability = need;
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

int devtmpfs_poll(vfs_node_t node, size_t events) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return EPOLLNVAL;
    if ((tnode->node->type & file_block) || (tnode->node->type & file_stream)) {
        return device_poll(tnode->node->rdev, events);
    }
    return -ENOSYS;
}

void devtmpfs_resize(vfs_node_t node, uint64_t size) {
    devtmpfs_node_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;

    if (size == 0) {
        handle->size = 0;
        if (handle->node)
            handle->node->size = 0;
        return;
    }

    size_t new_capability = size;
    void *new_content = alloc_frames_bytes(new_capability);
    if (!new_content)
        return;

    memcpy(new_content, handle->content, MIN(new_capability, handle->size));
    if (new_capability > (size_t)handle->size) {
        memset((uint8_t *)new_content + handle->size, 0,
               new_capability - handle->size);
    }

    free_frames_bytes(handle->content, handle->capability);
    handle->content = new_content;
    handle->capability = new_capability;
    handle->size = size;
    if (handle->node)
        handle->node->size = size;
}

int devtmpfs_stat(vfs_node_t node) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return -EINVAL;
    node->size = tnode->size;
    return 0;
}

void devtmpfs_free_handle(vfs_node_t node) {
    devtmpfs_node_t *tnode = node ? node->handle : NULL;
    if (!tnode)
        return;
    free_frames_bytes(tnode->content, tnode->capability);
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
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_NEED_OPEN,
};

ssize_t inputdev_open(void *data, void *arg) {
    dev_input_event_t *event = data;
    event->timesOpened++;
    return 0;
}

ssize_t inputdev_close(void *data, void *arg) {
    dev_input_event_t *event = data;
    event->timesOpened--;
    return 0;
}

ssize_t inputdev_event_read(void *data, void *buf, uint64_t offset,
                            uint64_t len, uint64_t flags) {
    dev_input_event_t *event = data;

    // while (!circular_int_read_poll(&event->device_events)) {
    //     if (flags & O_NONBLOCK) {
    //         arch_disable_interrupt();
    //         return -EWOULDBLOCK;
    //     }
    //     arch_enable_interrupt();
    //     schedule(SCHED_FLAG_YIELD);
    // }
    // arch_disable_interrupt();

    ssize_t cnt = circular_int_read(&event->device_events, buf, len);

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
        vfs_node_t device_node = vfs_open((const char *)path, 0);
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

void devtmpfs_init_umount() {
    llist_delete(&devtmpfs_root->node_for_childs);
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
    tm time;
    time_read(&time);
    uint32_t seed = mktime(&time);
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
    vfs_node_t tty_node = vfs_open(default_console, 0);
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

void circular_int_init(circular_int_t *circ, size_t size) {
    circ->read_ptr = 0;
    circ->write_ptr = 0;
    circ->buff_size = size;
    circ->buff = malloc(size);
    mutex_init(&circ->lock);
    memset(circ->buff, 0, size);
}

size_t circular_int_read(circular_int_t *circ, uint8_t *buff, size_t length) {
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    if (write == read) {
        return 0;
    }

    mutex_lock(&circ->lock);

    size_t toCopy = MIN(CIRC_READABLE(write, read, circ->buff_size), length);

    for (int i = 0; i < toCopy; i++) {
        // todo: could optimize this with edge memcpy() operations
        buff[i] = circ->buff[read];
        read = (read + 1) % circ->buff_size;
    }

    circ->read_ptr = read;

    mutex_unlock(&circ->lock);

    return toCopy;
}

size_t circular_int_write(circular_int_t *circ, const uint8_t *buff,
                          size_t length) {
    mutex_lock(&circ->lock);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    size_t writable = CIRC_WRITABLE(write, read, circ->buff_size);
    if (length > writable) {
        mutex_unlock(&circ->lock);
        return 0; // cannot do this
    }

    for (size_t i = 0; i < length; i++) {
        // todo: could optimize this with edge memcpy() operations
        circ->buff[write] = buff[i];
        write = (write + 1) % circ->buff_size;
    }

    circ->write_ptr = write;

    mutex_unlock(&circ->lock);

    return length;
}

size_t circular_int_read_poll(circular_int_t *circ) {
    size_t ret = 0;
    mutex_lock(&circ->lock);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    ret = CIRC_READABLE(write, read, circ->buff_size);
    mutex_unlock(&circ->lock);
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
