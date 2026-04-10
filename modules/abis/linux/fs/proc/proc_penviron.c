#include <fs/proc/proc.h>
#include <task/task.h>

size_t proc_penviron_stat(proc_handle_t *handle) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);

    if (!task || task->env_end <= task->env_start)
        return 0;

    return task->env_end - task->env_start;
}

size_t proc_penviron_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);

    if (!task || task->env_end <= task->env_start)
        return 0;

    return procfs_task_region_read(task, task->env_start, task->env_end, addr,
                                   offset, size);
}
