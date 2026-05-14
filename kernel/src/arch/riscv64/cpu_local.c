#include <arch/riscv64/cpu_local.h>
#include <arch/riscv64/smp/smp.h>
#include <task/task_struct.h>

static riscv64_cpu_local_t riscv64_cpu_locals[MAX_CPU_NUM];

riscv64_cpu_local_t *riscv64_get_cpu_local(void) {
    uintptr_t local;
    asm volatile("csrr %0, sscratch" : "=r"(local));
    if (!local)
        asm volatile("mv %0, tp" : "=r"(local));
    return (riscv64_cpu_local_t *)local;
}

riscv64_cpu_local_t *riscv64_get_cpu_local_by_id(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return NULL;
    return &riscv64_cpu_locals[cpu_id];
}

void riscv64_cpu_local_init(uint32_t cpu_id, uint64_t hartid) {
    if (cpu_id >= MAX_CPU_NUM)
        return;

    riscv64_cpu_local_t *local = &riscv64_cpu_locals[cpu_id];
    memset(local, 0, sizeof(*local));
    local->cpu_id = cpu_id;
    local->hartid = hartid;
    asm volatile("mv tp, %0" : : "r"(local) : "memory");
    asm volatile("csrw sscratch, %0" : : "r"(local) : "memory");
}

void riscv64_cpu_local_set_current(task_t *current) {
    riscv64_cpu_local_t *local = riscv64_get_cpu_local();
    if (!local)
        return;

    local->task_ptr = current;
    local->syscall_stack = current ? current->syscall_stack : 0;
}

uint32_t riscv64_current_cpu_id(void) {
    riscv64_cpu_local_t *local = riscv64_get_cpu_local();
    return local ? local->cpu_id : get_cpuid_by_hartid(current_hartid());
}
