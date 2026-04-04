#include <fs/proc/proc.h>
#include <task/task.h>

size_t proc_mounts_stat(proc_handle_t *handle) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    size_t content_len = 0;
    char *content = procfs_generate_mount_table(task, false, &content_len);
    free(content);
    return content_len;
}

size_t proc_mounts_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    size_t content_len = 0;
    char *content = procfs_generate_mount_table(task, false, &content_len);

    if (!content)
        return 0;
    if (offset >= content_len) {
        free(content);
        return 0;
    }

    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}
