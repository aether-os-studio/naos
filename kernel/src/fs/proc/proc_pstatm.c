#include <fs/proc/proc.h>
#include <task/task.h>

char *proc_gen_statm_file(task_t *task, size_t *content_len) {
    char *buffer = malloc(PAGE_SIZE * 4);
    procfs_task_mem_stats_t stats;

    if (!buffer) {
        *content_len = 0;
        return NULL;
    }

    procfs_task_mem_stats(task, &stats);
    int len = sprintf(buffer, "%llu %llu %llu %llu 0 %llu 0\n",
                      (unsigned long long)stats.size_pages,
                      (unsigned long long)stats.resident_pages,
                      (unsigned long long)stats.shared_pages,
                      (unsigned long long)stats.text_pages,
                      (unsigned long long)stats.data_pages);
    *content_len = len;

    return buffer;
}

size_t proc_pstatm_stat(proc_handle_t *handle) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_statm_file(task, &content_len);
    if (!content)
        return 0;
    free(content);
    return content_len;
}

size_t proc_pstatm_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_statm_file(task, &content_len);
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
