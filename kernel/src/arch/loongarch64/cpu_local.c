#include <arch/loongarch64/cpu_local.h>

static loongarch64_cpu_local_t loongarch64_cpu_locals[MAX_CPU_NUM];
static loongarch64_cpu_local_t *current_cpu_local = &loongarch64_cpu_locals[0];

loongarch64_cpu_local_t *loongarch64_get_cpu_local(void) {
    return current_cpu_local;
}

loongarch64_cpu_local_t *loongarch64_get_cpu_local_by_id(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        cpu_id = 0;
    return &loongarch64_cpu_locals[cpu_id];
}

void loongarch64_cpu_local_init(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        cpu_id = 0;

    loongarch64_cpu_local_t *local = &loongarch64_cpu_locals[cpu_id];
    memset(local, 0, sizeof(*local));
    local->cpu_id = cpu_id;
    current_cpu_local = local;
}

void loongarch64_cpu_local_set_current(task_t *current) {
    loongarch64_get_cpu_local()->task_ptr = current;
}

uint32_t loongarch64_current_cpu_id(void) {
    return loongarch64_get_cpu_local()->cpu_id;
}
