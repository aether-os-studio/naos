#include <drivers/usb/usb.h>
#include <fs/sys.h>

static bool usb_sysfs_registered;

static const char *usb_sysfs_speed(uint8_t speed) {
    switch (speed) {
    case USB_LOWSPEED:
        return "1.5";
    case USB_FULLSPEED:
        return "12";
    case USB_HIGHSPEED:
        return "480";
    case USB_SUPERSPEED:
        return "5000";
    default:
        return "0";
    }
}

static void usb_controller_path(const usb_controller_t *cntl, char *path,
                                size_t size) {
    snprintf(path, size, "/sys/devices/usb/usb%u", cntl->busnum);
}

static void usb_device_path(const usb_device_t *usbdev, char *path,
                            size_t size) {
    snprintf(path, size, "/sys/devices/usb/%s", usbdev->topology);
}

static void usb_bus_entry_path(const char *name, char *path, size_t size) {
    snprintf(path, size, "/sys/bus/usb/devices/%s", name);
}

static void usb_interface_name(const usb_device_t *usbdev,
                               const usb_device_interface_t *iface, char *name,
                               size_t size) {
    snprintf(name, size, "%s:1.%u", usbdev->topology,
             iface->iface->bInterfaceNumber);
}

static void usb_interface_path(const usb_device_t *usbdev,
                               const usb_device_interface_t *iface, char *path,
                               size_t size) {
    char name[64];

    usb_interface_name(usbdev, iface, name, sizeof(name));
    snprintf(path, size, "/sys/devices/usb/%s/%s", usbdev->topology, name);
}

static void usb_devpath_fragment(const usb_device_t *usbdev, char *path,
                                 size_t size) {
    const char *dash = strchr(usbdev->topology, '-');
    if (!dash || !dash[1]) {
        snprintf(path, size, "0");
        return;
    }

    snprintf(path, size, "%s", dash + 1);
}

static void sysfs_ensure_symlink(vfs_node_t *parent, const char *name,
                                 const char *target_path) {
    char *parent_path = vfs_get_fullpath(parent);
    char path[512];

    snprintf(path, sizeof(path), "%s/%s", parent_path, name);
    free(parent_path);

    if (vfs_open(path, O_NOFOLLOW))
        return;
    sysfs_child_append_symlink(parent, name, target_path);
}

static void usb_sysfs_write_controller(usb_controller_t *cntl) {
    char path[128];
    char pci_path[128];
    char name[16];

    usb_controller_path(cntl, path, sizeof(path));
    snprintf(name, sizeof(name), "usb%u", cntl->busnum);

    vfs_node_t *root = sysfs_ensure_dir(path);
    if (!root)
        return;

    sysfs_write_attrf(root, "busnum", "%u", cntl->busnum);
    sysfs_ensure_symlink(root, "subsystem", "/sys/bus/usb");

    if (cntl->pci) {
        snprintf(pci_path, sizeof(pci_path),
                 "/sys/bus/pci/devices/%04x:%02x:%02x.%u", cntl->pci->segment,
                 cntl->pci->bus, cntl->pci->slot, cntl->pci->func);
        sysfs_ensure_symlink(root, "device", pci_path);
    }

    vfs_node_t *bus_root = sysfs_ensure_dir("/sys/bus/usb/devices");
    if (bus_root)
        sysfs_ensure_symlink(bus_root, name, path);
}

static void usb_sysfs_write_interface(const usb_device_t *usbdev,
                                      const usb_device_interface_t *iface,
                                      const char *dev_path) {
    char name[64];
    char iface_path[192];
    char bus_entry[192];
    vfs_node_t *root;
    vfs_node_t *bus_root;

    usb_interface_name(usbdev, iface, name, sizeof(name));
    usb_interface_path(usbdev, iface, iface_path, sizeof(iface_path));
    usb_bus_entry_path(name, bus_entry, sizeof(bus_entry));

    root = sysfs_ensure_dir(iface_path);
    if (!root)
        return;

    sysfs_write_attrf(root, "bInterfaceNumber", "%u",
                      iface->iface->bInterfaceNumber);
    sysfs_write_attrf(root, "bAlternateSetting", "%u",
                      iface->iface->bAlternateSetting);
    sysfs_write_attrf(root, "bNumEndpoints", "%u", iface->iface->bNumEndpoints);
    sysfs_write_attrf(root, "bInterfaceClass", "%02x",
                      iface->iface->bInterfaceClass);
    sysfs_write_attrf(root, "bInterfaceSubClass", "%02x",
                      iface->iface->bInterfaceSubClass);
    sysfs_write_attrf(root, "bInterfaceProtocol", "%02x",
                      iface->iface->bInterfaceProtocol);
    sysfs_ensure_symlink(root, "subsystem", "/sys/bus/usb");
    sysfs_ensure_symlink(root, "device", dev_path);

    bus_root = sysfs_ensure_dir("/sys/bus/usb/devices");
    if (bus_root)
        sysfs_ensure_symlink(bus_root, name, iface_path);
}

static void usb_sysfs_write_device(usb_device_t *usbdev) {
    char path[192];
    char bus_entry[192];
    char devpath[32];
    vfs_node_t *root;
    vfs_node_t *bus_root;

    usb_device_path(usbdev, path, sizeof(path));
    usb_bus_entry_path(usbdev->topology, bus_entry, sizeof(bus_entry));
    usb_devpath_fragment(usbdev, devpath, sizeof(devpath));

    root = sysfs_ensure_dir(path);
    if (!root)
        return;

    sysfs_write_attrf(root, "busnum", "%u", usbdev->busnum);
    sysfs_write_attrf(root, "devnum", "%u", usbdev->devnum);
    sysfs_write_attrf(root, "devpath", "%s", devpath);
    sysfs_write_attrf(root, "speed", "%s", usb_sysfs_speed(usbdev->speed));
    sysfs_write_attrf(root, "idVendor", "%04x", usbdev->vendorid);
    sysfs_write_attrf(root, "idProduct", "%04x", usbdev->productid);
    sysfs_write_attrf(root, "bDeviceClass", "%02x",
                      usbdev->device_desc.bDeviceClass);
    sysfs_write_attrf(root, "bDeviceSubClass", "%02x",
                      usbdev->device_desc.bDeviceSubClass);
    sysfs_write_attrf(root, "bDeviceProtocol", "%02x",
                      usbdev->device_desc.bDeviceProtocol);
    sysfs_write_attrf(root, "bNumConfigurations", "%u",
                      usbdev->device_desc.bNumConfigurations);
    if (usbdev->config) {
        sysfs_write_attrf(root, "bConfigurationValue", "%u",
                          usbdev->config->bConfigurationValue);
        sysfs_write_attrf(root, "bNumInterfaces", "%u",
                          usbdev->config->bNumInterfaces);
    }
    if (usbdev->manufacturer[0])
        sysfs_write_attr(root, "manufacturer", usbdev->manufacturer);
    if (usbdev->product[0])
        sysfs_write_attr(root, "product", usbdev->product);
    if (usbdev->serial[0])
        sysfs_write_attr(root, "serial", usbdev->serial);
    sysfs_ensure_symlink(root, "subsystem", "/sys/bus/usb");

    bus_root = sysfs_ensure_dir("/sys/bus/usb/devices");
    if (bus_root)
        sysfs_ensure_symlink(bus_root, usbdev->topology, path);

    for (int i = 0; i < usbdev->ifaces_num; i++)
        usb_sysfs_write_interface(usbdev, &usbdev->ifaces[i], path);
}

static void usb_sysfs_remove_controller(usb_controller_t *cntl) {
    char path[128];
    char bus_entry[128];
    char name[16];

    usb_controller_path(cntl, path, sizeof(path));
    snprintf(name, sizeof(name), "usb%u", cntl->busnum);
    usb_bus_entry_path(name, bus_entry, sizeof(bus_entry));

    sysfs_detach_path(bus_entry, true);
    sysfs_detach_path(path, false);
}

static void usb_sysfs_remove_device(usb_device_t *usbdev) {
    char path[192];
    char bus_entry[192];

    for (int i = 0; i < usbdev->ifaces_num; i++) {
        char name[64];
        char iface_path[192];
        char iface_bus_entry[192];

        usb_interface_name(usbdev, &usbdev->ifaces[i], name, sizeof(name));
        usb_interface_path(usbdev, &usbdev->ifaces[i], iface_path,
                           sizeof(iface_path));
        usb_bus_entry_path(name, iface_bus_entry, sizeof(iface_bus_entry));

        sysfs_detach_path(iface_bus_entry, true);
        sysfs_detach_path(iface_path, false);
    }

    usb_device_path(usbdev, path, sizeof(path));
    usb_bus_entry_path(usbdev->topology, bus_entry, sizeof(bus_entry));
    sysfs_detach_path(bus_entry, true);
    sysfs_detach_path(path, false);
}

static usb_bus_notifier_ops_t usb_sysfs_notifier = {
    .controller_add = usb_sysfs_write_controller,
    .controller_remove = usb_sysfs_remove_controller,
    .device_add = usb_sysfs_write_device,
    .device_remove = usb_sysfs_remove_device,
};

void usb_sysfs_init(void) {
    if (usb_sysfs_registered)
        return;

    sysfs_ensure_dir("/sys/devices/usb");
    sysfs_ensure_dir("/sys/bus/usb/devices");
    usb_register_bus_notifier(&usb_sysfs_notifier);
    usb_sysfs_registered = true;
}
