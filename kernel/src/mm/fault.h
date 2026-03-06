#pragma once

#include <mm/mm.h>
#include <task/task.h>

typedef enum page_fault_result {
    PF_RES_OK,
    PF_RES_SEGF,
    PF_RES_NOMEM,
} page_fault_result_t;

enum {
    PF_ACCESS_READ = 1UL << 0,
    PF_ACCESS_WRITE = 1UL << 1,
    PF_ACCESS_EXEC = 1UL << 2,
    PF_FROM_USER = 1UL << 3,
    PF_PROTECTION = 1UL << 4,
};

page_fault_result_t handle_page_fault_ex(task_t *task, uint64_t vaddr,
                                         uint64_t fault_flags);
page_fault_result_t handle_page_fault(task_t *task, uint64_t vaddr);
