#include <arch/arch.h>
#include <drivers/kernel_logger.h>

uint64_t cpu_count = 0;

__attribute__((used, section(".limine_requests"))) static volatile struct limine_mp_request mp_request = {
    .id = LIMINE_MP_REQUEST,
    .revision = 0,
};

extern void ap_entry(struct limine_mp_info *cpu);

void smp_init()
{
    cpu_count = mp_request.response->cpu_count;

    for (uint64_t i = 0; i < mp_request.response->cpu_count; i++)
    {
        struct limine_mp_info *cpu = mp_request.response->cpus[i];
        if (cpu->mpidr == mp_request.response->bsp_mpidr)
            continue;

        cpu->goto_address = ap_entry;
    }
}

void ap_kmain(struct limine_mp_info *cpu)
{
    arch_disable_interrupt();

    setup_vectors();

    while (1)
    {
        arch_pause();
    }
}
