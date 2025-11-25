#include <libs/klibc.h>
#include <boot/boot.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <dev/device.h>
#include <drivers/tty.h>
#include <mod/dlinker.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/proc.h>

extern void acpi_init();

void kmain(void) {
    arch_disable_interrupt();

    boot_init();

    frame_init();

    page_table_init();

    heap_init();

    irq_manager_init();

    acpi_init();

    arch_early_init();

    device_init();

    vfs_init();

    devtmpfs_init();

    tty_init();

    printk("Aether-OS starting...\n");

    stdio_init();

    proc_init();

    dlinker_init();

    task_init();

    arch_init();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
