#include <fs/vfs/vfs.h>
#include <fs/vfs/sys.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <net/netlink.h>

vfs_node_t sysfs_root = NULL;

extern uint32_t device_number;

#define PCI_CLASS_DISPLAY 0x03
#define PCI_SUBCLASS_DISPLAY_VGA 0x00

#define IS_VGA(c) (((c) & 0x00ffff00) == ((PCI_CLASS_DISPLAY << 16) | (PCI_SUBCLASS_DISPLAY_VGA << 8)))

void sysfs_init()
{
    vfs_mkdir("/sys");
    sysfs_root = vfs_open("/sys");

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

    for (uint32_t i = 0; i < pci_device_number; i++)
    {
        pci_device_t *dev = pci_devices[i];
        if (dev == NULL)
            continue;

        char name[128];
        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d", dev->segment, dev->bus, dev->slot, dev->func);

        vfs_mkdir(name);

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/class", dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        char content[64];
        sprintf(content, "0x%x", dev->class_code);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/revision", dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%02x", dev->revision_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/vendor", dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%04x", dev->vendor_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));

        sprintf(name, "/sys/bus/pci/devices/%04d:%02d:%02d.%d/device", dev->segment, dev->bus, dev->slot, dev->func);
        vfs_mkfile(name);

        sprintf(content, "0x%04x", dev->device_id);
        vfs_write(vfs_open(name), content, 0, strlen(content));
    }

    // #if defined(__x86_64__)
    //     vfs_node_t devices_platform = vfs_child_append(devices_root, "platform", NULL);
    //     devices_platform->type = file_dir;
    //     devices_platform->mode = 0644;
    //     vfs_node_t devices_platform_i8042 = vfs_child_append(devices_platform, "i8042", NULL);
    //     devices_platform_i8042->type = file_dir;
    //     devices_platform_i8042->mode = 0644;

    //     vfs_node_t serio0 = vfs_child_append(devices_platform_i8042, "serio0", NULL);
    //     serio0->type = file_dir;
    //     serio0->mode = 0644;
    //     vfs_node_t serio1 = vfs_child_append(devices_platform_i8042, "serio1", NULL);
    //     serio1->type = file_dir;
    //     serio1->mode = 0644;

    //     vfs_node_t serio0_input = vfs_child_append(serio0, "input", NULL);
    //     serio0_input->type = file_dir;
    //     serio0_input->mode = 0644;
    //     vfs_node_t serio1_input = vfs_child_append(serio1, "input", NULL);
    //     serio1_input->type = file_dir;
    //     serio1_input->mode = 0644;

    //     vfs_node_t input0 = vfs_child_append(serio0_input, "input0", NULL);
    //     input0->type = file_dir;
    //     input0->mode = 0644;
    //     handle = malloc(sizeof(sysfs_handle_t));
    //     handle->node = input0;
    //     input0->handle = handle;
    //     vfs_node_t input1 = vfs_child_append(serio1_input, "input1", NULL);
    //     input1->type = file_dir;
    //     input1->mode = 0644;
    //     handle = malloc(sizeof(sysfs_handle_t));
    //     handle->node = input1;
    //     input1->handle = handle;

    //     vfs_node_t event0 = vfs_child_append(input0, "event0", NULL);
    //     event0->type = file_dir;
    //     event0->mode = 0644;

    //     vfs_node_t dev_node = vfs_child_append(char_dev, "13:0", NULL);
    //     dev_node->type = file_dir;
    //     dev_node->mode = 0644;
    //     dev_node->linkto = event0;

    //     vfs_node_t event1 = vfs_child_append(input1, "event1", NULL);
    //     event1->type = file_dir;
    //     event1->mode = 0644;

    //     dev_node = vfs_child_append(char_dev, "13:1", NULL);
    //     dev_node->type = file_dir;
    //     dev_node->mode = 0644;
    //     dev_node->linkto = event1;

    //     vfs_node_t device = vfs_child_append(input0, "device", NULL);
    //     device->type = file_dir | file_symlink;
    //     device->mode = 0644;
    //     device->linkto = input0;
    //     device = vfs_child_append(input1, "device", NULL);
    //     device->type = file_dir | file_symlink;
    //     device->mode = 0644;
    //     device->linkto = input1;

    //     vfs_node_t subsystem = vfs_child_append(event0, "subsystem", NULL);
    //     subsystem->type = file_dir | file_symlink;
    //     subsystem->mode = 0644;
    //     subsystem->linkto = input_root;
    //     subsystem = vfs_child_append(event1, "subsystem", NULL);
    //     subsystem->type = file_dir | file_symlink;
    //     subsystem->mode = 0644;
    //     subsystem->linkto = input_root;

    //     vfs_node_t uevent = vfs_child_append(event0, "uevent", NULL);
    //     uevent->type = file_none;
    //     uevent->mode = 0644;
    //     handle = malloc(sizeof(sysfs_handle_t));
    //     sprintf(handle->content, "MAJOR=13\nMINOR=0\nDEVNAME=input/event0\nID_INPUT=1\nID_INPUT_KEYBOARD=1\n");
    //     handle->node = uevent;
    //     uevent->handle = handle;
    //     uevent = vfs_child_append(event1, "uevent", NULL);
    //     uevent->type = file_none;
    //     uevent->mode = 0644;
    //     handle = malloc(sizeof(sysfs_handle_t));
    //     sprintf(handle->content, "MAJOR=13\nMINOR=1\nDEVNAME=input/event1\nID_INPUT=1\nID_INPUT_MOUSE=1\n");
    //     handle->node = uevent;
    //     uevent->handle = handle;
    // #endif
}

static int next_seq_num = 1;

int alloc_seq_num()
{
    return next_seq_num++;
}

vfs_node_t sysfs_regist_dev(char t, int major, int minor, const char *real_device_path, const char *dev_name, const char *other_uevent_content)
{
    const char *root = (t == 'c') ? "char" : "block";

    char dev_root_path[256];
    sprintf(dev_root_path, "/sys/dev/%s/%d:%d", root, major, minor);

    bool dev_root_is_real = (strlen(real_device_path) == 0);

    vfs_node_t real_device_node = NULL;
    if (dev_root_is_real)
    {
        vfs_mkdir(dev_root_path);
        real_device_node = vfs_open(dev_root_path);
    }
    else
    {
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
    sprintf(uevent_content, "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\nDEVPATH=%s\n%s", major, minor, dev_name, fullpath + 4, other_uevent_content);
    vfs_write(uevent_node, uevent_content, 0, strlen(uevent_content));

    free(fullpath);

    char buffer[256];
    sprintf(buffer, "add@/%s\nACTION=add\nSEQNUM=%d\n%s\n", dev_root_is_real ? dev_root_path : real_device_path, alloc_seq_num(), uevent_content);
    int len = strlen(buffer);
    for (int i = 0; i < len; i++)
    {
        if (buffer[i] == '\n')
            buffer[i] = '\0';
    }
    netlink_kernel_uevent_send(buffer, len);

    return real_device_node;
}

vfs_node_t sysfs_child_append(vfs_node_t parent, const char *name, bool is_dir)
{
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

vfs_node_t sysfs_child_append_symlink(vfs_node_t parent, const char *name, const char *target_path)
{
    char *parent_path = vfs_get_fullpath(parent);

    char path[512];
    sprintf(path, "%s/%s", parent_path, name);

    vfs_symlink(path, target_path);

    free(parent_path);

    return vfs_open(path);
}
