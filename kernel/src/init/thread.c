#include <arch/arch.h>
#include <task/task.h>

#include <fs/vfs/dev.h>
#include <drivers/bus/pci.h>
#include <drivers/fdt/fdt.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm.h>
#include <fs/partition.h>
#include <drivers/fb.h>

extern void acpi_init_after_pci();

extern void tmpfs_init();
extern void sysfs_init();
extern void sysfs_init_umount();
extern void fs_syscall_init();
extern void socketfs_init();
extern void pipefs_init();

extern void mount_root();

bool system_initialized = false;

extern bool can_schedule;

extern vfs_node_t devfs_root;

void init_thread(uint64_t arg) {
    printk("NAOS init thread is running...\n");

    arch_init_after_thread();

    pci_controller_init();
    pci_init();

#if !defined(__x86_64__)
    fdt_init();
#endif

    acpi_init_after_pci();

    fs_syscall_init();
    socketfs_init();
    pipefs_init();

    fbdev_init();

    tmpfs_init();

    sysfs_init();

    pci_init_after_sysfs();

    drm_init_after_pci_sysfs();

    fbdev_init_sysfs();

    arch_input_dev_init();

    sysfs_init_umount();

    mount_root();

    pci_init_after_mount_root();

    system_initialized = true;

    printk("System initialized, ready to go to userland.\n");

#if defined(__x86_64__)
    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/sbin/init";
    task_execve("/sbin/init", argvs, NULL);
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
