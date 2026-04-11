#include <fs/proc/proc.h>
#include <task/task.h>

char *proc_gen_statm_file(task_t *task, size_t *content_len) {
    char *buffer = malloc(PAGE_SIZE * 4);
    int len = sprintf(buffer, "%ld %ld %ld %ld %ld %ld %ld", 2000L, 1000L,
                      1000L, 10L, 0L, 20L, 0L);
    *content_len = len;

    return buffer;
}

size_t proc_pstatm_stat(proc_handle_t *handle) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_statm_file(task, &content_len);
    free(content);
    return content_len;
}

size_t proc_pstatm_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_statm_file(task, &content_len);
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
