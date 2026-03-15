#pragma once

#include <mm/mm.h>
#include <task/task.h>

typedef enum page_fault_result {
    PF_RES_OK,
    PF_RES_SEGF,
    PF_RES_NOMEM,
} page_fault_result_t;

typedef enum page_fault_access {
    PF_ACCESS_READ = 1U << 0,
    PF_ACCESS_WRITE = 1U << 1,
    PF_ACCESS_EXEC = 1U << 2,
    PF_ACCESS_USER = 1U << 3,
    PF_ACCESS_PRESENT = 1U << 4,
} page_fault_access_t;

page_fault_result_t handle_page_fault_flags(task_t *task, uint64_t vaddr,
                                            uint64_t fault_flags);
