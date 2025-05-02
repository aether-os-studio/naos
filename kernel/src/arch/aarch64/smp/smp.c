#include <arch/arch.h>
#include <arch/aarch64/acpi/gic.h>
#include <drivers/kernel_logger.h>
#include <task/task.h>

uint64_t cpu_count = 0;

__attribute__((used, section(".limine_requests"))) static volatile struct limine_mp_request mp_request = {
    .id = LIMINE_MP_REQUEST,
    .revision = 0,
};

extern void ap_entry(struct limine_mp_info *cpu);

uint64_t cpuid_to_mpidr[MAX_CPU_NUM];

uint64_t current_mpidr()
{
    uint64_t mpidr;
    asm volatile(
        "mrs %0, mpidr_el1" // 读取MPIDR_EL1寄存器
        : "=r"(mpidr));
    return mpidr & 0xFF;
}

uint64_t get_cpuid_by_mpidr(uint64_t mpidr)
{
    for (uint64_t i = 0; i < cpu_count; i++)
        if (cpuid_to_mpidr[i] == mpidr)
            return i;

    printk("Cannot get cpu id, mpidr = %d\n", mpidr);

    return 0;
}

void smp_init()
{
    memset(cpuid_to_mpidr, 0, sizeof(cpuid_to_mpidr));

    cpu_count = mp_request.response->cpu_count;

    for (uint64_t i = 0; i < mp_request.response->cpu_count; i++)
    {
        struct limine_mp_info *cpu = mp_request.response->cpus[i];
        cpuid_to_mpidr[cpu->processor_id] = cpu->mpidr;

        if (cpu->mpidr == mp_request.response->bsp_mpidr)
            continue;

        cpu->goto_address = ap_entry;
    }
}

extern bool task_initialized;

void ap_kmain(struct limine_mp_info *cpu)
{
    arch_disable_interrupt();

    setup_vectors();

    while (!task_initialized)
    {
        asm volatile("nop");
    }

    arch_set_current(idle_tasks[current_cpu_id]);

    gic_v3_init_percpu();

    timer_init_percpu();

    arch_enable_interrupt();

    while (1)
    {
        arch_pause();
    }
}
