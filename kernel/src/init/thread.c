#include <arch/arch.h>
#include <task/task.h>
#include <init/abis.h>
#include <drivers/bus/pci.h>
#include <drivers/fdt/fdt.h>
#include <fs/partition.h>
#include <net/real_socket.h>

extern void acpi_init_after_pci();

extern void notifyfs_init();

bool system_initialized = false;

extern bool can_schedule;

void init_thread(uint64_t arg) {
    printk("NAOS init thread is running...\n");

    arch_init_after_thread();

    pci_controller_init();

#if !defined(__x86_64__)
    fdt_init();
#endif

    pci_init();

    acpi_init_after_pci();

    real_socket_init();

    notifyfs_init();

    system_abi->init_after_thread();

    arch_input_dev_init();

    system_abi->init_before_user();

    system_initialized = true;

    printk("System initialized, ready to go to userland.\n");

    system_abi->run_user_init("/init");

    printk("run init failed\n");

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}
