#include <fs/vfs/sys.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>

static vfs_node_t sysfs_root = NULL;
static int sysfs_id = 0;

static vfs_node_t devices_root = NULL;
static vfs_node_t dev_root = NULL;
static vfs_node_t bus_root = NULL;
static vfs_node_t class_root = NULL;
static vfs_node_t pci_root = NULL;
static vfs_node_t pci_devices_root = NULL;
static vfs_node_t input_root = NULL;
static vfs_node_t graphics_root = NULL;

static int dummy()
{
    return 0;
}

void sysfs_open(void *parent, const char *name, vfs_node_t node)
{
    sysfs_handle_t *parent_handle = parent;
}

int sysfs_stat(void *file, vfs_node_t node)
{
    return 0;
}

ssize_t sysfs_read(void *file, void *addr, size_t offset, size_t size)
{
    if (!file)
        return 0;

    sysfs_handle_t *handle = file;

    if (handle->private_data != NULL)
    {
        if (offset >= DEFAULT_PAGE_SIZE)
            return 0;
        size_t toCopy = DEFAULT_PAGE_SIZE - offset;
        if (toCopy > size)
            toCopy = size;

        pci_device_t *device = handle->private_data;

        for (size_t i = 0; i < toCopy; i++)
        {
            uint16_t word = device->op->read(device->bus, device->slot, device->func, device->segment, offset++) & 0xFFFF;
            ((uint8_t *)addr)[i] = (uint8_t)EXPORT_BYTE(word, true);
        }

        return toCopy;
    }
    else
    {
        size_t content_len = strlen(handle->content);

        if (offset >= content_len)
        {
            return 0;
        }

        size_t remaining = content_len - offset;
        size_t read_size = (size < remaining) ? size : remaining;

        memcpy(addr, handle->content + offset, read_size);
        return read_size;
    }
}

ssize_t sysfs_readlink(void *file, void *addr, size_t offset, size_t size)
{
    sysfs_handle_t *handle = file;
    if (!handle)
        return 0;
    vfs_node_t node = handle->node;

    vfs_node_t original_node = node;
    while (original_node->link_by)
    {
        original_node = original_node->link_by;
    }

    if (original_node->linkname)
    {
        size_t len = strnlen(original_node->linkname, size);
        memcpy(addr, original_node->linkname, len);
        ((char *)addr)[len] = '\0';
        return len;
    }

    return -ENOLINK;
}

int sysfs_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

static struct vfs_callback callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = sysfs_open,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)sysfs_read,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_read_t)sysfs_readlink,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = sysfs_stat,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = sysfs_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

extern uint32_t device_number;

#define PCI_CLASS_DISPLAY 0x03
#define PCI_SUBCLASS_DISPLAY_VGA 0x00

#define IS_VGA(c) (((c) & 0x00ffff00) == ((PCI_CLASS_DISPLAY << 16) | (PCI_SUBCLASS_DISPLAY_VGA << 8)))

void sysfs_init()
{
    sysfs_id = vfs_regist("sysfs", &callback);
    sysfs_root = vfs_node_alloc(rootdir, "sys");
    sysfs_root->type = file_dir;
    sysfs_root->fsid = sysfs_id;
    sysfs_root->mode = 0644;
    devices_root = vfs_child_append(sysfs_root, "devices", NULL);
    devices_root->type = file_dir;
    devices_root->mode = 0644;
    dev_root = vfs_child_append(sysfs_root, "dev", NULL);
    dev_root->type = file_dir;
    dev_root->mode = 0644;
    bus_root = vfs_child_append(sysfs_root, "bus", NULL);
    bus_root->type = file_dir;
    bus_root->mode = 0644;
    class_root = vfs_child_append(sysfs_root, "class", NULL);
    class_root->type = file_dir;
    class_root->mode = 0644;
    pci_root = vfs_child_append(bus_root, "pci", NULL);
    pci_root->type = file_dir;
    pci_root->mode = 0644;
    graphics_root = vfs_child_append(class_root, "graphics", NULL);
    graphics_root->type = file_dir;
    graphics_root->mode = 0644;
    input_root = vfs_child_append(class_root, "input", NULL);
    input_root->type = file_dir;
    input_root->mode = 0644;
    pci_devices_root = vfs_child_append(pci_root, "devices", NULL);
    pci_devices_root->type = file_dir;
    pci_devices_root->mode = 0644;

    for (uint32_t i = 0; i < pci_device_number; i++)
    {
        pci_device_t *dev = pci_devices[i];
        if (dev == NULL)
            continue;

        char dirname[128];
        sprintf(dirname, "%04d:%02d:%02d.%d", dev->segment, dev->bus, dev->slot, dev->func);

        vfs_node_t pci_device_dir = vfs_child_append(pci_devices_root, dirname, dev);
        pci_device_dir->type = file_dir;
        pci_device_dir->mode = 0644;

        vfs_node_t class_file = vfs_child_append(pci_device_dir, "class", NULL);
        class_file->type = file_none;
        class_file->handle = malloc(sizeof(sysfs_handle_t));
        sysfs_handle_t *class_handle = class_file->handle;
        class_handle->node = class_file;
        class_handle->private_data = NULL;
        uint32_t class_code = dev->op->read(dev->bus, dev->slot, dev->func, dev->segment, 0x0a) << 8;
        class_code |= ((uint32_t)dev->revision_id) << 8;
        sprintf(class_handle->content, "0x%x\n", class_code);

        vfs_node_t revision_file = vfs_child_append(pci_device_dir, "revision", NULL);
        revision_file->type = file_none;
        revision_file->handle = malloc(sizeof(sysfs_handle_t));
        sysfs_handle_t *revision_handle = revision_file->handle;
        revision_handle->node = revision_file;
        revision_handle->private_data = NULL;
        sprintf(revision_handle->content, "0x%02x\n", dev->revision_id);

        vfs_node_t vendor_file = vfs_child_append(pci_device_dir, "vendor", NULL);
        vendor_file->type = file_none;
        vendor_file->handle = malloc(sizeof(sysfs_handle_t));
        sysfs_handle_t *vendor_handle = vendor_file->handle;
        vendor_handle->node = vendor_file;
        vendor_handle->private_data = NULL;
        sprintf(vendor_handle->content, "0x%04x\n", dev->vendor_id);

        vfs_node_t device_file = vfs_child_append(pci_device_dir, "device", NULL);
        device_file->type = file_none;
        device_file->handle = malloc(sizeof(sysfs_handle_t));
        sysfs_handle_t *device_handle = device_file->handle;
        device_handle->node = device_file;
        device_handle->private_data = NULL;
        sprintf(device_handle->content, "0x%04x\n", dev->device_id);

        vfs_node_t config_file = vfs_child_append(pci_device_dir, "config", dev);
        config_file->type = file_none;
        config_file->handle = malloc(sizeof(sysfs_handle_t));
        config_file->fsid = sysfs_id;
        sysfs_handle_t *config_handle = config_file->handle;
        config_handle->private_data = dev;
        config_handle->node = config_file;
    }

    vfs_node_t char_dev = vfs_child_append(dev_root, "char", NULL);
    char_dev->type = file_dir;
    char_dev->mode = 0644;
    vfs_node_t dev_node = vfs_child_append(char_dev, "226:0", NULL);
    dev_node->type = file_dir;
    dev_node->mode = 0644;
    vfs_node_t device_node = vfs_child_append(dev_node, "device", NULL);
    device_node->type = file_dir;
    device_node->mode = 0644;
    dev_node = vfs_child_append(char_dev, "13:0", NULL);
    dev_node->type = file_dir | file_symlink;
    dev_node->mode = 0644;
#if defined(__x86_64__)
    dev_node->linkname = strdup("../../devices/platform/i8042/serio0/input/input0");
#endif
    device_node = vfs_child_append(dev_node, "device", NULL);
    device_node->type = file_dir;
    device_node->mode = 0644;
    dev_node = vfs_child_append(char_dev, "13:1", NULL);
    dev_node->type = file_dir | file_symlink;
    dev_node->mode = 0644;
#if defined(__x86_64__)
    dev_node->linkname = strdup("../../devices/platform/i8042/serio1/input/input1");
#endif

#if defined(__x86_64__)
    vfs_node_t devices_platform = vfs_child_append(devices_root, "platform", NULL);
    devices_platform->type = file_dir;
    devices_platform->mode = 0644;
    vfs_node_t devices_platform_i8042 = vfs_child_append(devices_platform, "i8042", NULL);
    devices_platform_i8042->type = file_dir;
    devices_platform_i8042->mode = 0644;

    vfs_node_t serio0 = vfs_child_append(devices_platform_i8042, "serio0", NULL);
    serio0->type = file_dir;
    serio0->mode = 0644;
    vfs_node_t serio1 = vfs_child_append(devices_platform_i8042, "serio1", NULL);
    serio1->type = file_dir;
    serio1->mode = 0644;

    vfs_node_t serio0_input = vfs_child_append(serio0, "input", NULL);
    serio0_input->type = file_dir;
    serio0_input->mode = 0644;
    vfs_node_t serio1_input = vfs_child_append(serio1, "input", NULL);
    serio1_input->type = file_dir;
    serio1_input->mode = 0644;

    vfs_node_t input0 = vfs_child_append(serio0_input, "input0", NULL);
    input0->type = file_dir;
    input0->mode = 0644;
    sysfs_handle_t *handle = malloc(sizeof(sysfs_handle_t));
    handle->node = input0;
    input0->handle = handle;
    vfs_node_t input1 = vfs_child_append(serio1_input, "input1", NULL);
    input1->type = file_dir;
    input1->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    handle->node = input1;
    input1->handle = handle;

    vfs_node_t subsystem = vfs_child_append(input0, "subsystem", NULL);
    subsystem->type = file_dir;
    subsystem->mode = 0644;
    subsystem = vfs_child_append(input1, "subsystem", NULL);
    subsystem->type = file_dir;
    subsystem->mode = 0644;

    vfs_node_t uevent = vfs_child_append(input0, "uevent", NULL);
    uevent->type = file_none;
    uevent->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    sprintf(handle->content, "DEVNAME=input/event0\nDEVPATH=/devices/platform/i8042/serio0/input/input0\nSUBSYSTEM=input\n");
    handle->node = uevent;
    uevent->handle = handle;
    uevent = vfs_child_append(input1, "uevent", NULL);
    uevent->type = file_none;
    uevent->mode = 0644;
    handle = malloc(sizeof(sysfs_handle_t));
    sprintf(handle->content, "DEVNAME=input/event1\nDEVPATH=/devices/platform/i8042/serio1/input/input1\nSUBSYSTEM=input\n");
    handle->node = uevent;
    uevent->handle = handle;

    vfs_node_t capabilities = vfs_child_append(input0, "capabilities", NULL);
    capabilities->type = file_dir;
    capabilities->mode = 0644;
    vfs_node_t key = vfs_child_append(capabilities, "key", NULL);
    key->type = file_none;
    key->mode = 0700;
    capabilities = vfs_child_append(input1, "capabilities", NULL);
    capabilities->type = file_dir;
    capabilities->mode = 0644;
    vfs_node_t rel = vfs_child_append(capabilities, "rel", NULL);
    rel->type = file_none;
    rel->mode = 0700;
#endif
}
