#include <fs/proc.h>
#include <cgroup/cgroup.h>
#include <task/task.h>

size_t proc_pcgroup_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    char *text = cgroup_task_proc_text(task);
    size_t len = text ? strlen(text) : strlen("0::/\n");
    free(text);
    return len;
}

size_t proc_pcgroup_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    char *text = cgroup_task_proc_text(task);
    const char *content = text ? text : "0::/\n";
    size_t content_len;

    content_len = strlen(content);
    if (offset >= content_len) {
        free(text);
        return 0;
    }
    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(text);
    return to_copy;
}
