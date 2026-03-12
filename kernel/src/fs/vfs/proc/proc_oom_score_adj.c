#include <fs/vfs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

size_t proc_oom_score_adj_stat(proc_handle_t *handle) {
    (void)handle;
    return 2;
}

int proc_oom_score_adj_poll(proc_handle_t *handle, int events) {
    (void)handle;
    (void)events;
    int revents = 0;
    return revents;
}

size_t proc_oom_score_adj_read(proc_handle_t *handle, void *addr, size_t offset,
                               size_t size) {
    (void)handle;

    static const char content[] = "0\n";
    size_t len = sizeof(content) - 1;

    if (!addr || offset >= len || size == 0)
        return 0;

    size_t copy_len = MIN(size, len - offset);
    memcpy(addr, content + offset, copy_len);
    return copy_len;
}
