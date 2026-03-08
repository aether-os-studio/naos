#include <arch/x64/cpu_local.h>
#include <arch/x64/acpi/normal.h>
#include <arch/x64/io.h>
#include <arch/x64/task/fsgsbase.h>
#include <mm/mm.h>
#include <task/task_struct.h>
#include <mod/dlinker.h>

static x64_cpu_local_t x64_cpu_locals[MAX_CPU_NUM];

x64_cpu_local_t *x64_get_cpu_local(void) {
    return (x64_cpu_local_t *)read_kgsbase();
}

x64_cpu_local_t *x64_get_cpu_local_by_id(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return NULL;
    return &x64_cpu_locals[cpu_id];
}

void x64_cpu_local_init(uint32_t cpu_id, uint32_t lapic_id_value) {
    if (cpu_id >= MAX_CPU_NUM)
        return;

    x64_cpu_local_t *local = &x64_cpu_locals[cpu_id];
    memset(local, 0, sizeof(*local));
    local->cpu_id = cpu_id;
    local->lapic_id = lapic_id_value;
    write_kgsbase((uint64_t)local);
}

void x64_cpu_local_set_current(task_t *current) {
    x64_cpu_local_t *local = x64_get_cpu_local();
    if (!local) {
        uint32_t lapic = (uint32_t)lapic_id();
        uint32_t cpu_id = get_cpuid_by_lapic_id(lapic);
        x64_cpu_local_init(cpu_id, lapic);
        local = x64_get_cpu_local();
        if (!local)
            return;
    }

    local->task_ptr = current;
    local->current_mm = current ? current->mm : NULL;
    local->syscall_stack = current ? current->syscall_stack : 0;
}

void x64_cpu_local_sync_syscall_stack(task_t *task) {
    x64_cpu_local_t *local = x64_get_cpu_local();
    if (!local)
        return;
    if (!task || local->task_ptr != task)
        return;
    local->syscall_stack = task->syscall_stack;
}

uint32_t x64_current_cpu_id(void) {
    x64_cpu_local_t *local = x64_get_cpu_local();
    if (local)
        return local->cpu_id;
    return get_cpuid_by_lapic_id((uint32_t)lapic_id());
}
EXPORT_SYMBOL(x64_current_cpu_id);
