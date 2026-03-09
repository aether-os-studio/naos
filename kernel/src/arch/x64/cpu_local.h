#pragma once

#include <libs/klibc.h>

struct task;
typedef struct task task_t;
struct task_mm_info;
typedef struct task_mm_info task_mm_info_t;

typedef struct x64_cpu_local {
    uint64_t syscall_stack;
    task_t *task_ptr;
    task_mm_info_t *current_mm;
    uint64_t user_rsp_scratch;
    uint32_t cpu_id;
    uint32_t lapic_id;
} x64_cpu_local_t;

x64_cpu_local_t *x64_get_cpu_local(void);
x64_cpu_local_t *x64_get_cpu_local_by_id(uint32_t cpu_id);
void x64_cpu_local_init(uint32_t cpu_id, uint32_t lapic_id);
void x64_cpu_local_set_current(task_t *current);
void x64_cpu_local_sync_syscall_stack(task_t *task);
uint32_t x64_current_cpu_id(void);
