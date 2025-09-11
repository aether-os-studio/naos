#include <arch/arch.h>
#include <task/task.h>

#include <fs/vfs/dev.h>
#include <drivers/bus/pci.h>
#include <drivers/drm/drm_core.h>
#include <drivers/drm/drm.h>
#include <fs/partition.h>
#include <drivers/fb.h>

extern void fatfs_init();
extern void iso9660_init();
extern void sysfs_init();
extern void fs_syscall_init();
extern void pipefs_init();
extern void socketfs_init();

extern void mount_root();

bool system_initialized = false;

extern bool can_schedule;

void init_thread(uint64_t arg)
{
    printk("NAOS init thread is running...\n");

    arch_disable_interrupt();
    can_schedule = false;

    pci_init();

    partition_init();

    fs_syscall_init();
    socketfs_init();
    pipefs_init();
    iso9660_init();
    fatfs_init();

    mount_root();

    fbdev_init();

    sysfs_init();

    pci_init_after_sysfs();

    fbdev_init_sysfs();

    dev_init_after_sysfs();

    arch_input_dev_init();

    system_initialized = true;

    printk("System initialized, ready to go to userland.\n");

    can_schedule = true;
    arch_enable_interrupt();

    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/sbin/init";
    task_execve("/sbin/init", argvs, NULL);

    printk("run init failed\n");

    while (1)
    {
        arch_pause();
    }
}
