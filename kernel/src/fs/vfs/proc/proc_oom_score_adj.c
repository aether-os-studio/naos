#include <fs/vfs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

size_t proc_oom_score_adj_stat(proc_handle_t *handle) { return 0; }

int proc_oom_score_adj_poll(proc_handle_t *handle, int events) {
    int revents = 0;
    return revents;
}

size_t proc_oom_score_adj_read(proc_handle_t *handle, void *addr, size_t offset,
                               size_t size) {
    return -EPERM;
}
