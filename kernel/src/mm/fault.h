#pragma once

#include <mm/mm.h>
#include <task/task.h>

typedef enum page_fault_result {
    PF_RES_OK,
    PF_RES_SEGF,
    PF_RES_NOMEM,
} page_fault_result_t;

page_fault_result_t handle_page_fault(task_t *task, uint64_t vaddr);
