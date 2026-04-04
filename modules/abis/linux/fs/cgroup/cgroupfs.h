#pragma once

#include <fs/vfs/vfs.h>

struct task;
typedef struct task task_t;

void cgroupfs_init(void);
char *cgroupfs_task_path(task_t *task);
