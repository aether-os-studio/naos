#pragma once

#include <libs/klibc.h>

struct task;
typedef struct task task_t;

typedef struct riscv64_cpu_local {
    uint64_t syscall_stack;
    uint64_t user_sp_scratch;
    uint64_t trap_t0_scratch;
    task_t *task_ptr;
    uint32_t cpu_id;
    uint32_t reserved0;
    uint64_t hartid;
} riscv64_cpu_local_t;

riscv64_cpu_local_t *riscv64_get_cpu_local(void);
riscv64_cpu_local_t *riscv64_get_cpu_local_by_id(uint32_t cpu_id);
void riscv64_cpu_local_init(uint32_t cpu_id, uint64_t hartid);
void riscv64_cpu_local_set_current(task_t *current);
uint32_t riscv64_current_cpu_id(void);
