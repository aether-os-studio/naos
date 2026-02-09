#include <arch/arch.h>
#include <task/task.h>
#include <drivers/fdt/fdt.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <libs/keys.h>

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

extern void cpu_init();

void arch_early_init() {
    arch_set_current(NULL);

    init_serial();
    fw_cfg_init();
    ramfb_init();
    trap_init();
    cpu_init();
    csr_write(sscratch, 0);
    smp_init();
}

void arch_init() {
    syscall_handler_init();
    timer_init_hart(cpuid_to_hartid[current_cpu_id]);
}

void arch_init_after_thread() {}

extern dev_input_event_t *kb_input_event;
extern dev_input_event_t *mouse_input_event;

void arch_input_dev_init() {
    kb_input_event = malloc(sizeof(dev_input_event_t));
    kb_input_event->inputid.bustype = 0x11;
    kb_input_event->inputid.vendor = 0x0000;
    kb_input_event->inputid.product = 0x0000;
    kb_input_event->inputid.version = 0x0000;
    kb_input_event->event_bit = kb_event_bit;
    kb_input_event->device_events.read_ptr = 0;
    kb_input_event->device_events.write_ptr = 0;
    kb_input_event->clock_id = CLOCK_MONOTONIC;
    strncpy(kb_input_event->uniq, "ps2kbd", sizeof(kb_input_event->uniq));
    kb_input_event->devname = strdup("input/event0");
    circular_int_init(&kb_input_event->device_events, DEFAULT_PAGE_SIZE);
    uint64_t kbd_dev = device_install(
        DEV_CHAR, DEV_INPUT, kb_input_event, "input/event0", 0, inputdev_ioctl,
        inputdev_poll, inputdev_event_read, inputdev_event_write, NULL);

    sysfs_regist_dev('c', (kbd_dev >> 8) & 0xFF, kbd_dev & 0xFF,
                     "/sys/devices/platform/i8042/serio0/input/input0/event0",
                     "input/event0",
                     "ID_INPUT=1\nID_INPUT_KEYBOARD=1\nSUBSYSTEM=input\n");

    vfs_node_t input_root = vfs_open("/sys/class/input", 0);
    vfs_node_t event0 = sysfs_child_append_symlink(
        input_root, "event0",
        "/sys/devices/platform/i8042/serio0/input/input0/event0");

    event0 =
        vfs_open("/sys/devices/platform/i8042/serio0/input/input0/event0", 0);
    sysfs_child_append_symlink(event0, "subsystem", "/sys/class/input", 0);

    mouse_input_event = malloc(sizeof(dev_input_event_t));
    mouse_input_event->inputid.bustype = 0x11;
    mouse_input_event->inputid.vendor = 0x0000;
    mouse_input_event->inputid.product = 0x0000;
    mouse_input_event->inputid.version = 0x0000;
    mouse_input_event->event_bit = mouse_event_bit;
    mouse_input_event->device_events.read_ptr = 0;
    mouse_input_event->device_events.write_ptr = 0;
    mouse_input_event->clock_id = CLOCK_MONOTONIC;
    strncpy(mouse_input_event->uniq, "ps2mouse",
            sizeof(mouse_input_event->uniq));
    mouse_input_event->devname = strdup("input/event1");
    circular_int_init(&mouse_input_event->device_events, DEFAULT_PAGE_SIZE);
    uint64_t mouse_dev =
        device_install(DEV_CHAR, DEV_INPUT, mouse_input_event, "input/event1",
                       0, inputdev_ioctl, inputdev_poll, inputdev_event_read,
                       inputdev_event_write, NULL);

    sysfs_regist_dev('c', (mouse_dev >> 8) & 0xFF, mouse_dev & 0xFF,
                     "/sys/devices/platform/i8042/serio1/input/input1/event1",
                     "input/event1",
                     "ID_INPUT=1\nID_INPUT_MOUSE=1\nSUBSYSTEM=input\n");

    input_root = vfs_open("/sys/class/input", 0);
    vfs_node_t event1 = sysfs_child_append_symlink(
        input_root, "event1",
        "/sys/devices/platform/i8042/serio1/input/input1/event1");

    event1 =
        vfs_open("/sys/devices/platform/i8042/serio1/input/input1/event1", 0);
    sysfs_child_append_symlink(event1, "subsystem", "/sys/class/input");
}
