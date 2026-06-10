#include <libs/klibc.h>
#include <boot/boot.h>
#include <init/callbacks.h>
#include <drivers/logger.h>
#include <mm/mm.h>
#include <mm/slub.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <dev/device.h>
#include <drivers/tty.h>
#include <drivers/smbios.h>
#include <mod/dlinker.h>
#include <task/signal.h>
#include <task/task.h>
#include <cgroup/cgroup.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/notify.h>
#include <fs/vfs/cgroup/cgroupfs.h>
#include <fs/tmp.h>
#include <fs/dev.h>
#include <fs/sys.h>
#include <fs/proc.h>
#include <fs/initramfs.h>
#include <fs/fs_syscall.h>
#include <drivers/drm/drm.h>
#include <drivers/deadline.h>

extern void acpi_init();

int on_sched_update(void) {
    drm_handle_vblank_tick();
    timerfd_check_wakeup();
    return 0;
}

int on_new_task(task_t *task) {
    procfs_on_new_task(task);
    cgroupfs_on_new_task(task);
    return 0;
}

int on_exit_task(task_t *task) {
    cgroupfs_on_exit_task(task);
    procfs_on_exit_task(task);
    return 0;
}

int on_open_file(task_t *task, int fd) {
    procfs_on_open_file(task, fd);
    return 0;
}

int on_close_file(task_t *task, int fd, fd_t *file) {
    procfs_on_close_file(task, fd);
    return 0;
}

int on_new_device(device_t *dev) {
    devfs_register_device(dev);
    return 0;
}

int on_remove_device(device_t *dev) {
    devfs_unregister_device(dev);
    return 0;
}

int on_new_bus_device(bus_device_t *dev) {
    sysfs_register_device(dev);
    return 0;
}

int on_remove_bus_device(bus_device_t *dev) {
    sysfs_unregister_device(dev);
    return 0;
}

void kmain(void) {
    arch_disable_interrupt();

    boot_init();

    frame_init();

    kmalloc_init();

    page_table_init();

    irq_manager_init();

    smbios_init();

    acpi_init();

    arch_early_init();

    device_init();

    vfs_init();

    notifyfs_init();

    tmpfs_init();

    initramfs_init();

    dlinker_init();

    devtmpfs_init();
    sysfs_init();
    cgroup_init();

    regist_on_sched_update_callback(on_sched_update);
    regist_on_new_task_callback(on_new_task);
    regist_on_exit_task_callback(on_exit_task);
    regist_on_open_file_callback(on_open_file);
    regist_on_close_file_callback(on_close_file);
    regist_on_new_device_callback(on_new_device);
    regist_on_remove_device_callback(on_remove_device);
    regist_on_new_bus_device_callback(on_new_bus_device);
    regist_on_remove_bus_device_callback(on_remove_bus_device);

    tty_init();

    printk("Aether-OS starting...\n");

    signal_init();

    devfs_nodes_init();

    futex_init();

    proc_init();

    task_init();

    printk("Task initialized...\n");

    arch_init();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
