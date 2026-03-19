#include <dev/input.h>
#include <fs/dev.h>
#include <fs/sys.h>

static int eventn = 0;
#define INPUT_EVENT_RING_SIZE (DEFAULT_PAGE_SIZE * 32)

spinlock_t inputdev_regist_lock = SPIN_INIT;

extern vfs_node_t *devtmpfs_root;

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
    if (!input_event) {
        spin_unlock(&inputdev_regist_lock);
        return NULL;
    }
    memset(input_event, 0, sizeof(dev_input_event_t));
    input_event->inputid.bustype = 0x11;
    input_event->inputid.vendor = 0x0000;
    input_event->inputid.product = 0x0000;
    input_event->inputid.version = 0x0000;
    input_event->event_bit = event_bit;
    input_event->clock_id = CLOCK_MONOTONIC;
    strncpy(input_event->uniq, device_name, sizeof(input_event->uniq));
    input_event->devname = strdup(dirpath);
    input_event->event_queue_capacity =
        INPUT_EVENT_RING_SIZE / sizeof(struct input_event);
    if (input_event->event_queue_capacity == 0) {
        input_event->event_queue_capacity = 128;
    }
    input_event->event_queue =
        calloc(input_event->event_queue_capacity, sizeof(struct input_event));
    if (!input_event->event_queue) {
        free(input_event->devname);
        free(input_event);
        spin_unlock(&inputdev_regist_lock);
        return NULL;
    }
    spin_init(&input_event->event_queue_lock);

    uint64_t dev = device_install(DEV_CHAR, DEV_INPUT, input_event, dirpath, 0,
                                  inputdev_open, inputdev_close, inputdev_ioctl,
                                  inputdev_poll, inputdev_event_read,
                                  inputdev_event_write, NULL);
    if (!dev) {
        free(input_event->devname);
        free(input_event->event_queue);
        free(input_event);
        spin_unlock(&inputdev_regist_lock);
        return NULL;
    }
    input_event->timesOpened = 0;
    input_event->devnode = vfs_open_at(devtmpfs_root, dirpath, 0);
    if (input_event->devnode) {
        vfs_close(input_event->devnode);
    }

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

    vfs_node_t *input_root = sysfs_open_node("/sys/class/input", 0);
    vfs_node_t *eventn_node =
        sysfs_child_append_symlink(input_root, dirname, sysfs_path);

    eventn_node = sysfs_open_node(sysfs_path, 0);
    sysfs_child_append_symlink(eventn_node, "subsystem", "/sys/class/input");

    eventn++;

    spin_unlock(&inputdev_regist_lock);

    return input_event;
}
