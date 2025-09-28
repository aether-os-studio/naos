#pragma once

#include <fs/vfs/vfs.h>

typedef struct proc_handle {
    char name[64];
    char content[256];
    vfs_node_t node;
    task_t *task;
} proc_handle_t;

ssize_t procfs_read(fd_t *file, void *addr, size_t offset, size_t size);

#define MAX_PID_NAME_LEN 16

void proc_init();

void procfs_on_new_task(task_t *task);
void procfs_on_exit_task(task_t *task);
