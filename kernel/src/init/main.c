#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>

__attribute__((used, section(".limine_requests"))) static volatile LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end"))) static volatile LIMINE_REQUESTS_END_MARKER;

void kmain(void)
{
    if (LIMINE_BASE_REVISION_SUPPORTED == false)
    {
        while (1)
        {
            arch_pause();
        }
    }

    frame_init();
    printk("Next Aether-OS starting...\n");

    heap_init();

    arch_early_init();

    task_init();

    arch_init();

    while (1)
    {
        arch_pause();
    }
}
