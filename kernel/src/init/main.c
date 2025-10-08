#include <libs/klibc.h>
#include <boot/boot.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <interrupt/irq_manager.h>
#include <mod/dlinker.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/proc.h>

void kmain(void) {
    arch_disable_interrupt();

    boot_init();

    frame_init();

    page_table_init();

    heap_init();

    printk("Next Aether-OS starting...\n");

    arch_early_init();

    irq_manager_init();

    vfs_init();

    dev_init();

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
