#include <drivers/input.h>
#include <fs/vfs/sys.h>

static int eventn = 0;

spinlock_t inputdev_regist_lock = SPIN_INIT;

dev_input_event_t *regist_input_dev(const char *device_name,
                                    const char *uevent_append,
                                    input_event_from_t from,
                                    event_bit_t event_bit) {
    spin_lock(&inputdev_regist_lock);

    char dirname[16];
    sprintf(dirname, "event%d", eventn);

    char dirpath[32];
    sprintf(dirpath, "input/%s", dirname);

    dev_input_event_t *input_event = malloc(sizeof(dev_input_event_t));
    input_event->inputid.bustype = 0x11;
    input_event->inputid.vendor = 0x0000;
    input_event->inputid.product = 0x0000;
    input_event->inputid.version = 0x0000;
    input_event->event_bit = event_bit;
    input_event->device_events.read_ptr = 0;
    input_event->device_events.write_ptr = 0;
    input_event->clock_id = CLOCK_MONOTONIC;
    strncpy(input_event->uniq, device_name, sizeof(input_event->uniq));
    input_event->devname = strdup(dirpath);
    circular_int_init(&input_event->device_events, DEFAULT_PAGE_SIZE);
    uint64_t dev = device_install(
        DEV_CHAR, DEV_INPUT, input_event, dirpath, 0, inputdev_ioctl,
        inputdev_poll, inputdev_event_read, inputdev_event_write, NULL);
    input_event->timesOpened = 1;

    char uevent[128];
    sprintf(uevent, "ID_INPUT=1\n%s\nSUBSYSTEM=input\n", uevent_append);

    char sysfs_path[128];
    memset(sysfs_path, 0, sizeof(sysfs_path));
    if (from == INPUT_FROM_PS2) {
        sprintf(sysfs_path,
                "/sys/devices/platform/i8042/serio%d/input%d/event%d", eventn,
                eventn, eventn);
    } else if (from == INPUT_FROM_USB) {
        sprintf(sysfs_path, "/sys/devices/usb/input/input%d/event%d", eventn,
                eventn);
    }

    sysfs_regist_dev('c', (dev >> 8) & 0xFF, dev & 0xFF, sysfs_path, dirpath,
                     uevent);

    vfs_node_t input_root = vfs_open("/sys/class/input", 0);
    vfs_node_t eventn_node =
        sysfs_child_append_symlink(input_root, dirname, sysfs_path);

    eventn_node = vfs_open(sysfs_path, 0);
    sysfs_child_append_symlink(eventn_node, "subsystem", "/sys/class/input");

    eventn++;

    spin_unlock(&inputdev_regist_lock);

    return input_event;
}
