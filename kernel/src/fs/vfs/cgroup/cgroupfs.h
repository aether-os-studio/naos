#pragma once

#include <fs/vfs/vfs.h>

struct task;
typedef struct task task_t;

void cgroupfs_init(void);
char *cgroupfs_task_path(task_t *task);
int cgroupfs_set_task_cgroup_by_fd(task_t *task, int fd);
void cgroupfs_on_new_task(task_t *task);
void cgroupfs_on_exit_task(task_t *task);
