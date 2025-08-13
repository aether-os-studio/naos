#include <arch/arch.h>
#include <task/task.h>

#include <fs/vfs/dev.h>
#include <drivers/bus/pci.h>
#include <drivers/drm/drm.h>
#include <drivers/virtio/virtio.h>
#include <fs/partition.h>
#include <drivers/fb.h>

#if defined(__x86_64__)
#include <drivers/gfx/vmware/vmware.h>
#endif

extern void ext_init();
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

    virtio_init();

    partition_init();

#if defined(__x86_64__)
    vmware_gpu_init();
#endif

    fs_syscall_init();
    socketfs_init();
    pipefs_init();
    iso9660_init();
    fatfs_init();

    mount_root();

    fbdev_init();
    // drm_init();

    sysfs_init();

    fbdev_init_sysfs();
    // drm_init_sysfs();

    dev_init_after_sysfs();

    arch_input_dev_init();

    system_initialized = true;

    can_schedule = true;
    arch_enable_interrupt();

    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/bin/bash";

    task_execve("/bin/bash", argvs, NULL);

    printk("run /bin/bash failed\n");

    while (1)
    {
        arch_pause();
    }
}
