#include <arch/aarch64/cpu_local.h>
#include <mm/mm.h>
#include <task/task_struct.h>
#include <mod/dlinker.h>

static aarch64_cpu_local_t aarch64_cpu_locals[MAX_CPU_NUM];

aarch64_cpu_local_t *aarch64_get_cpu_local(void) {
    uint64_t tpidr_el1;
    asm volatile("mrs %0, TPIDR_EL1" : "=r"(tpidr_el1));
    return (aarch64_cpu_local_t *)tpidr_el1;
}

aarch64_cpu_local_t *aarch64_get_cpu_local_by_id(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return NULL;
    return &aarch64_cpu_locals[cpu_id];
}

void aarch64_cpu_local_init(uint32_t cpu_id, uint32_t mpidr_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return;

    aarch64_cpu_local_t *local = &aarch64_cpu_locals[cpu_id];
    memset(local, 0, sizeof(*local));
    local->cpu_id = cpu_id;
    local->mpidr = mpidr_id;
    asm volatile("msr TPIDR_EL1, %0" ::"r"(local));
}

void aarch64_cpu_local_set_current(task_t *current) {
    aarch64_cpu_local_t *local = aarch64_get_cpu_local();
    if (!local) {
        return;
    }

    local->task_ptr = current;
    local->kernel_stack = current ? current->kernel_stack : 0;
}

uint32_t aarch64_current_cpu_id(void) {
    aarch64_cpu_local_t *local = aarch64_get_cpu_local();
    if (local)
        return local->cpu_id;
    return get_cpuid_by_mpidr(current_mpidr());
}
