#pragma once

#include <libs/klibc.h>

struct task;
typedef struct task task_t;

typedef struct aarch64_cpu_local {
    uint64_t kernel_stack;
    uint64_t user_rsp_scratch;
    task_t *task_ptr;
    uint32_t cpu_id;
    uint32_t mpidr;
} aarch64_cpu_local_t;

aarch64_cpu_local_t *aarch64_get_cpu_local(void);
aarch64_cpu_local_t *aarch64_get_cpu_local_by_id(uint32_t cpu_id);
void aarch64_cpu_local_init(uint32_t cpu_id, uint32_t mpidr_id);
void aarch64_cpu_local_set_current(task_t *current);
uint32_t aarch64_current_cpu_id(void);
