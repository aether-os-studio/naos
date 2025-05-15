#pragma once

#include <fs/vfs/vfs.h>

typedef struct procfs_handle
{
    vfs_node_t node;
    task_t *task;
    char fn[64];
} procfs_handle_t;

void proc_init();

vfs_node_t procfs_regist_proc(task_t *task);
void procfs_unregist_proc(task_t *task);
