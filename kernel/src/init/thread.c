#include <arch/arch.h>
#include <task/task.h>
#include <init/abis.h>
#include <drivers/bus/pci.h>
#include <drivers/fdt/fdt.h>
#include <fs/vfs/notify.h>
#include <block/partition.h>
#include <net/real_socket.h>

extern void acpi_init_after_pci();

bool system_initialized = false;

extern bool can_schedule;

extern void pidfd_init();

void init_thread(uint64_t arg) {
    printk("NAOS init thread is running...\n");

    arch_init_after_thread();

    pci_controller_init();

#if !defined(__x86_64__)
    fdt_init();
#endif

    pidfd_init();

    system_abi->init_after_thread();

    pci_init();

    acpi_init_after_pci();

    arch_input_dev_init();

    real_socket_init();

    system_abi->init_before_user();

    system_initialized = true;

    printk("System initialized, ready to go to userland.\n");

    const char *argvs[2];
    memset(argvs, 0, sizeof(argvs));
    argvs[0] = "/init";
    task_execve("/init", argvs, NULL);

    printk("run init failed\n");

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
