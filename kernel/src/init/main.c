#include <libs/klibc.h>
#include <boot/boot.h>
#include <init/callbacks.h>
#include <drivers/logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <dev/device.h>
#include <drivers/tty.h>
#include <drivers/smbios.h>
#include <mod/dlinker.h>
#include <task/signal.h>
#include <task/task.h>
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

static void signal_fill_signalfd_siginfo(struct signalfd_siginfo *sinfo,
                                         int sig, const siginfo_t *info) {
    memset(sinfo, 0, sizeof(*sinfo));
    sinfo->ssi_signo = info ? info->si_signo : sig;
    sinfo->ssi_errno = info ? info->si_errno : 0;
    sinfo->ssi_code = info ? info->si_code : SI_KERNEL;

    if (!info) {
        sinfo->ssi_pid = current_task ? current_task->pid : 0;
        sinfo->ssi_uid = current_task ? current_task->uid : 0;
        return;
    }

    switch (sig) {
    case SIGCHLD:
        sinfo->ssi_pid = info->_sifields._sigchld._pid;
        sinfo->ssi_uid = info->_sifields._sigchld._uid;
        sinfo->ssi_status = info->_sifields._sigchld._status;
        sinfo->ssi_utime = (uint64_t)info->_sifields._sigchld._utime;
        sinfo->ssi_stime = (uint64_t)info->_sifields._sigchld._stime;
        break;
    case SIGSEGV:
    case SIGBUS:
    case SIGILL:
    case SIGFPE:
    case SIGTRAP:
        sinfo->ssi_addr = (uint64_t)info->_sifields._sigfault._addr;
        break;
    default:
        if (info->si_code == SI_QUEUE || info->si_code == SI_TIMER ||
            info->si_code == SI_MESGQ || info->si_code == SI_ASYNCIO) {
            sinfo->ssi_pid = info->_sifields._rt._pid;
            sinfo->ssi_uid = info->_sifields._rt._uid;
            sinfo->ssi_int = info->_sifields._rt._sigval.sival_int;
            sinfo->ssi_ptr = (uint64_t)info->_sifields._rt._sigval.sival_ptr;
        } else {
            sinfo->ssi_pid = info->_sifields._kill._pid;
            sinfo->ssi_uid = info->_sifields._kill._uid;
        }
        break;
    }
}

void signal_notify_signalfd(task_t *task, int sig, const siginfo_t *info) {
    if (!task) {
        return;
    }

    fd_info_t *fd_info = task_fd_info_get(task);
    if (!fd_info)
        return;

    size_t signalfd_count = 0;
    struct vfs_file **targets = NULL;

    with_fd_info_lock(
        fd_info, ({
            signalfd_ref_t *pos, *tmp;

            llist_for_each(pos, tmp, &fd_info->signalfd_refs, node) {
                signalfd_count++;
            }

            if (signalfd_count == 0)
                break;

            targets = calloc(signalfd_count, sizeof(*targets));
            if (!targets)
                break;

            size_t idx = 0;
            llist_for_each(pos, tmp, &fd_info->signalfd_refs, node) {
                if (idx >= signalfd_count)
                    break;
                targets[idx++] = vfs_file_get(pos->file);
            }
        }));

    task_fd_info_put(fd_info, task);

    if (!targets)
        return;

    for (size_t i = 0; i < signalfd_count; i++) {
        struct vfs_file *fd = targets[i];
        if (!fd)
            continue;

        bool irq_state = arch_interrupt_enabled();
        arch_disable_interrupt();

        struct signalfd_ctx *ctx = signalfd_file_handle(fd);
        if (!ctx || !ctx->queue || ctx->queue_size == 0) {
            if (irq_state)
                arch_enable_interrupt();
            vfs_file_put(fd);
            continue;
        }

        sigset_t signalfd_mask = sigset_user_to_kernel(ctx->sigmask);
        if (signal_sig_maskable(sig) && !(signalfd_mask & signal_sigbit(sig))) {
            if (irq_state)
                arch_enable_interrupt();
            vfs_file_put(fd);
            continue;
        }

        struct signalfd_siginfo sinfo;
        signal_fill_signalfd_siginfo(&sinfo, sig, info);

        memcpy(&ctx->queue[ctx->queue_head], &sinfo, sizeof(sinfo));
        ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_size;
        if (ctx->queue_head == ctx->queue_tail) {
            ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
        }

        if (irq_state)
            arch_enable_interrupt();
        vfs_file_put(fd);
    }

    free(targets);
}

int on_send_signal(task_t *task, int sig, const siginfo_t *info) {
    signal_notify_signalfd(task, sig, info);
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

    regist_on_sched_update_callback(on_sched_update);
    regist_on_send_signal_callback(on_send_signal);
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

    deadline_reprogram_local();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
