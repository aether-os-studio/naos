#include <fs/vfs/proc.h>

size_t proc_pcgroup_stat(proc_handle_t *handle) { return 0; }

size_t proc_pcgroup_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    /* We do not expose per-task cgroup membership yet. Returning the root
     * hierarchy is more compatible than advertising a scope path that does
     * not actually exist in cgroupfs. */
    const char *content = "0::/\n";
    int content_len = strlen(content);
    if (offset > content_len)
        return 0;
    strncpy(addr, content + offset, content_len);
    return MIN(content_len, size);
}
