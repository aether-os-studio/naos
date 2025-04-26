#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/block/ahci/ahci.h>
#include <drivers/block/nvme/nvme.h>

__attribute__((used, section(".limine_requests"))) static volatile LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end"))) static volatile LIMINE_REQUESTS_END_MARKER;

// Halt and catch fire function.
static void hcf(void)
{
    for (;;)
    {
#if defined(__x86_64__)
        asm("hlt");
#elif defined(__aarch64__) || defined(__riscv)
        asm("wfi");
#elif defined(__loongarch64)
        asm("idle 0");
#endif
    }
}

void kmain(void)
{
    if (LIMINE_BASE_REVISION_SUPPORTED == false)
    {
        hcf();
    }

    frame_init();
    printk("Next Aether-OS starting...\n");

    heap_init();

    arch_early_init();

    pci_init();
    ahci_init();
    nvme_init();

    arch_init();

    hcf();
}
