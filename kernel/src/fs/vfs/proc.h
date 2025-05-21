#pragma once

#include <fs/vfs/vfs.h>

typedef struct proc_handle
{
    char name[64];
    char content[256];
    vfs_node_t node;
    task_t *task;
} proc_handle_t;

ssize_t procfs_read(void *file, void *addr, size_t offset, size_t size);

void proc_init();
