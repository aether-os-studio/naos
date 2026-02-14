#include <arch/arch.h>
#include <task/task.h>

#include <fs/vfs/dev.h>
#include <fs/vfs/ram.h>
#include <fs/vfs/configfs.h>
#include <drivers/bus/pci.h>
#include <drivers/fdt/fdt.h>
#include <drivers/drm/drm.h>
#include <fs/partition.h>
#include <drivers/fb.h>
#include <net/rtnl.h>
#include <net/real_socket.h>

extern void acpi_init_after_pci();

extern void sysfs_init();
extern void sysfs_init_umount();
extern void fsfdfs_init();
extern void cgroupfs_init();
extern void notifyfs_init();
extern void fs_syscall_init();
extern void socketfs_init();
extern void pipefs_init();

extern void mount_root();

bool system_initialized = false;

extern bool can_schedule;

void init_thread(uint64_t arg) {
    printk("NAOS init thread is running...\n");

    arch_init_after_thread();

    rtnl_init();

    futex_init();
    fs_syscall_init();
    ramfs_init();
    configfs_init();
    socketfs_init();
    pipefs_init();
    fsfdfs_init();
    cgroupfs_init();
    notifyfs_init();

    fbdev_init();

    pci_controller_init();

    sysfs_init();

#if !defined(__x86_64__)
    fdt_init();
#endif

    pci_init();

    acpi_init_after_pci();

    fbdev_init_sysfs();

    arch_input_dev_init();

    // drm_init_after_pci_sysfs();

    real_socket_init();

    devtmpfs_init_umount();
    sysfs_init_umount();

    // mount_root();

    system_initialized = true;

    printk("System initialized, ready to go to userland.\n");

#if defined(__x86_64__)
    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/init";
    task_execve("/init", argvs, NULL);
#else
    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/bin/bash";
    task_execve("/bin/bash", argvs, NULL);
#endif

    printk("run init failed\n");

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
