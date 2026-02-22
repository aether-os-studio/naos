#include <dev/device.h>
#include <fs/vfs/dev.h>
#include <mod/dlinker.h>

static device_t devices[DEVICE_NR]; // 设备数组
uint64_t devices_idxs[DEV_MAX];
spinlock_t device_lock = SPIN_INIT;

static device_t *get_null_device();

static bool device_minor_in_use(int subtype, uint64_t minor) {
    for (size_t i = 1; i < DEVICE_NR; i++) {
        device_t *device = &devices[i];
        if (device->type == DEV_NULL || device->subtype != subtype) {
            continue;
        }

        if ((device->dev & 0xFF) == minor) {
            return true;
        }
    }

    return false;
}

static uint64_t device_install_internal(int type, int subtype, void *ptr,
                                        char *name, uint64_t parent,
                                        void *open, void *close, void *ioctl,
                                        void *poll, void *read, void *write,
                                        void *map, bool use_fixed_minor,
                                        uint64_t fixed_minor) {
    if (subtype < 0 || subtype >= DEV_MAX) {
        return 0;
    }

    if (use_fixed_minor && fixed_minor > 0xFF) {
        return 0;
    }

    spin_lock(&device_lock);

    device_t *device = get_null_device();
    if (!device) {
        spin_unlock(&device_lock);
        return 0;
    }

    uint64_t dev_major = (uint64_t)subtype;
    uint64_t dev_minor = 0;

    if (use_fixed_minor) {
        if (device_minor_in_use(subtype, fixed_minor)) {
            spin_unlock(&device_lock);
            return 0;
        }

        dev_minor = fixed_minor;
        if (devices_idxs[subtype] <= dev_minor) {
            devices_idxs[subtype] = dev_minor + 1;
        }
    } else {
        dev_minor = devices_idxs[subtype]++;
    }

    device->ptr = ptr;
    device->parent = parent;
    device->type = type;
    device->subtype = subtype;
    device->dev = (dev_major << 8) | dev_minor;
    strncpy(device->name, name, NAMELEN);
    device->open = open;
    device->close = close;
    device->ioctl = ioctl;
    device->poll = poll;
    device->read = read;
    device->write = write;
    device->map = map;

    devfs_register_device(device);
    spin_unlock(&device_lock);

    return device->dev;
}

// 获取空设备
static device_t *get_null_device() {
    for (size_t i = 1; i < DEVICE_NR; i++) {
        device_t *device = &devices[i];
        if (device->type == DEV_NULL)
            return device;
    }
    return NULL;
}

ssize_t device_open(uint64_t dev, void *arg) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->open) {
        return device->open(device->ptr, arg);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_open);

ssize_t device_close(uint64_t dev) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->close) {
        return device->close(device->ptr);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_close);

ssize_t device_ioctl(uint64_t dev, int cmd, void *args) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->ioctl) {
        return device->ioctl(device->ptr, cmd, args);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_ioctl);

ssize_t device_poll(uint64_t dev, int events) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->poll) {
        return device->poll(device->ptr, events);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_poll);

ssize_t device_read(uint64_t dev, void *buf, uint64_t idx, size_t count,
                    uint64_t flags) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->read) {
        return device->read(device->ptr, buf, idx, count, flags);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_read);

ssize_t device_write(uint64_t dev, void *buf, uint64_t idx, size_t count,
                     uint64_t flags) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->write) {
        return device->write(device->ptr, buf, idx, count, flags);
    }
    return -ENOSYS;
}

EXPORT_SYMBOL(device_write);

void *device_map(uint64_t dev, void *addr, size_t offset, size_t size,
                 size_t prot, size_t flags) {
    device_t *device = device_get(dev);
    if (!device)
        return (void *)-ENODEV;
    if (device->map) {
        return device->map(device->ptr, addr, offset, size, prot, flags);
    }
    return (void *)-ENOSYS;
}

EXPORT_SYMBOL(device_map);

// 安装设备
uint64_t device_install(int type, int subtype, void *ptr, char *name,
                        uint64_t parent, void *open, void *close, void *ioctl,
                        void *poll, void *read, void *write, void *map) {
    return device_install_internal(type, subtype, ptr, name, parent, open,
                                   close, ioctl, poll, read, write, map, false,
                                   0);
}

uint64_t device_install_with_minor(int type, int subtype, void *ptr, char *name,
                                   uint64_t parent, void *open, void *close,
                                   void *ioctl, void *poll, void *read,
                                   void *write, void *map, uint64_t minor) {
    return device_install_internal(type, subtype, ptr, name, parent, open,
                                   close, ioctl, poll, read, write, map, true,
                                   minor);
}

void device_init() {
    memset(devices_idxs, 0, sizeof(devices_idxs));
    for (size_t i = 0; i < DEVICE_NR; i++) {
        device_t *device = &devices[i];
        memset(device, 0, sizeof(device_t));
        strcpy((char *)device->name, "null");
        device->type = DEV_NULL;
        device->subtype = DEV_NULL;
        device->dev = 0;
        device->parent = 0;
    }
}

device_t *device_find(int subtype, uint64_t idx) {
    uint64_t nr = 0;
    for (size_t i = 0; i < DEVICE_NR; i++) {
        device_t *device = &devices[i];
        if (device->subtype != subtype)
            continue;
        if (nr == idx)
            return device;
        nr++;
    }
    return NULL;
}

EXPORT_SYMBOL(device_find);

device_t *device_get(uint64_t dev) {
    for (size_t i = 0; i < DEVICE_NR; i++) {
        device_t *device = &devices[i];
        if (device->dev == dev)
            return device;
    }
    return NULL;
}

EXPORT_SYMBOL(device_get);
