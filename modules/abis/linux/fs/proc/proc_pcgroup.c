#include <fs/proc.h>
#include <fs/cgroup/cgroupfs.h>
#include <task/task.h>

size_t proc_pcgroup_stat(proc_handle_t *handle) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    char *path = cgroupfs_task_path(task);
    size_t len = path ? strlen(path) + strlen("0::\n") : strlen("0::/\n");
    free(path);
    return len;
}

size_t proc_pcgroup_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    char *path = cgroupfs_task_path(task);
    char buf[VFS_PATH_MAX];
    const char *cgroup_path = path ? path : "/";
    size_t content_len;

    snprintf(buf, sizeof(buf), "0::%s\n", cgroup_path);
    content_len = strlen(buf);
    if (offset >= content_len) {
        free(path);
        return 0;
    }
    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, buf + offset, to_copy);
    free(path);
    return to_copy;
}
