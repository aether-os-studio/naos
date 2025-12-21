#include <fs/vfs/proc/proc.h>
#include <task/task.h>

char *proc_gen_status_file(task_t *task, size_t *content_len) {
    char *buffer = calloc(1, 1);
    *content_len = 1;
    return buffer;
}

size_t proc_pstatus_stat(proc_handle_t *handle) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    free(content);
    return content_len;
}

size_t proc_pstatus_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    if (offset >= content_len) {
        free(content);
        return 0;
    }
    content_len = MIN(content_len, offset + size);
    size_t to_copy = MIN(content_len, size);
    memcpy(addr, content + offset, to_copy);
    free(content);
    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}
