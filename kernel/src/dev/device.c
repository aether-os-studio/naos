#include <dev/device.h>
#include <mod/dlinker.h>
#include <init/abis.h>
#include <init/callbacks.h>

DEFINE_LLIST(device_list);
uint64_t devices_idxs[DEV_MAX];
spinlock_t device_lock = SPIN_INIT;

static device_t *get_null_device();
static void device_reset_entry(device_t *device);

static bool device_minor_in_use(int subtype, uint64_t minor) {
    device_t *ptr, *tmp;
    llist_for_each(ptr, tmp, &device_list, node) {
        if (ptr->type == DEV_NULL || ptr->subtype != subtype) {
            continue;
        }

        if ((ptr->dev & 0xFF) == minor) {
            return true;
        }
    }

    return false;
}

static uint64_t device_install_internal(int type, int subtype, void *ptr,
                                        char *name, uint64_t parent, void *open,
                                        void *close, void *ioctl, void *poll,
                                        void *read, void *write, void *map,
                                        bool use_fixed_minor,
                                        uint64_t fixed_minor) {
    device_t *device;
    uint64_t devnr;

    if (subtype < 0 || subtype >= DEV_MAX) {
        return 0;
    }

    if (use_fixed_minor && fixed_minor > 0xFF) {
        return 0;
    }

    spin_lock(&device_lock);

    device = get_null_device();
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
    device->name = strdup(name);
    device->open = open;
    device->close = close;
    device->ioctl = ioctl;
    device->poll = poll;
    device->read = read;
    device->write = write;
    device->map = map;

    devnr = device->dev;
    spin_unlock(&device_lock);

    llist_append(&device_list, &device->node);

    on_new_device_call(device);

    return devnr;
}

// 获取空设备
static device_t *get_null_device() { return calloc(1, sizeof(device_t)); }

static void device_reset_entry(device_t *device) {
    if (!device)
        return;

    memset(device, 0, sizeof(*device));
    strcpy(device->name, "null");
    device->type = DEV_NULL;
    device->subtype = DEV_NULL;
    device->dev = 0;
    device->parent = 0;
}

ssize_t device_open(uint64_t dev, void *arg) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->open) {
        return device->open(device->ptr, arg);
    }
    return 0;
}

ssize_t device_close(uint64_t dev) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->close) {
        return device->close(device->ptr);
    }
    return 0;
}

ssize_t device_ioctl(uint64_t dev, int cmd, void *args, fd_t *fd) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->ioctl) {
        return device->ioctl(device->ptr, cmd, args, fd);
    }
    return -ENOSYS;
}

ssize_t device_poll(uint64_t dev, int events) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->poll) {
        return device->poll(device->ptr, events);
    }
    return -ENOSYS;
}

ssize_t device_read(uint64_t dev, void *buf, uint64_t idx, size_t count,
                    fd_t *fd) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->read) {
        return device->read(device->ptr, buf, idx, count, fd);
    }
    return -ENOSYS;
}

ssize_t device_write(uint64_t dev, void *buf, uint64_t idx, size_t count,
                     fd_t *fd) {
    device_t *device = device_get(dev);
    if (!device)
        return -ENODEV;
    if (device->write) {
        return device->write(device->ptr, buf, idx, count, fd);
    }
    return -ENOSYS;
}

void *device_map(uint64_t dev, void *addr, size_t offset, size_t size,
                 size_t prot, fd_t *fd) {
    device_t *device = device_get(dev);
    if (!device)
        return (void *)-ENODEV;
    if (device->map) {
        return device->map(device->ptr, addr, offset, size, prot, fd);
    }
    return (void *)-ENOSYS;
}

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

int device_uninstall(uint64_t dev) {
    device_t removed;
    int ret = -ENODEV;

    spin_lock(&device_lock);

    device_t *device = device_get(dev);
    if (!device || device->type == DEV_NULL) {
        spin_unlock(&device_lock);
        return ret;
    }

    memcpy(&removed, device, sizeof(removed));
    device_reset_entry(device);
    ret = 0;

    spin_unlock(&device_lock);

    on_remove_device_call(device);

    return ret;
}

void device_init() { memset(devices_idxs, 0, sizeof(devices_idxs)); }

device_t *device_find(int subtype, uint64_t idx) {
    uint64_t nr = 0;
    device_t *ptr, *tmp;
    llist_for_each(ptr, tmp, &device_list, node) {
        if (ptr->subtype != subtype)
            continue;
        if (nr == idx)
            return ptr;
        nr++;
    }
    return NULL;
}

device_t *device_get(uint64_t dev) {
    device_t *ptr, *tmp;
    llist_for_each(ptr, tmp, &device_list, node) {
        if (ptr->dev == dev)
            return ptr;
    }
    return NULL;
}
