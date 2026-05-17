#include <arch/loongarch64/cpu_local.h>
#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/smp/smp.h>
#include <task/task_struct.h>

static loongarch64_cpu_local_t loongarch64_cpu_locals[MAX_CPU_NUM];

loongarch64_cpu_local_t *loongarch64_get_cpu_local(void) {
    uintptr_t local;
    asm volatile("move %0, $r21" : "=r"(local));
    if (!local)
        local = csr_read(LOONGARCH_CSR_KS0);
    return (loongarch64_cpu_local_t *)local;
}

loongarch64_cpu_local_t *loongarch64_get_cpu_local_by_id(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return NULL;
    return &loongarch64_cpu_locals[cpu_id];
}

void loongarch64_cpu_local_init(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return;

    loongarch64_cpu_local_t *local = &loongarch64_cpu_locals[cpu_id];
    memset(local, 0, sizeof(*local));
    local->cpu_id = cpu_id;
    asm volatile("move $r21, %0" : : "r"(local) : "memory");
    csr_write(LOONGARCH_CSR_KS0, (uintptr_t)local);
}

void loongarch64_cpu_local_set_current(task_t *current) {
    loongarch64_cpu_local_t *local = loongarch64_get_cpu_local();
    if (!local)
        return;

    local->task_ptr = current;
    local->syscall_stack = current ? current->syscall_stack : 0;
    local->kernel_stack = current ? current->kernel_stack : 0;
}

uint32_t loongarch64_current_cpu_id(void) {
    loongarch64_cpu_local_t *local = loongarch64_get_cpu_local();
    if (local)
        return local->cpu_id;
    return get_cpuid_by_physid(csr_read(LOONGARCH_CSR_CPUID));
}
