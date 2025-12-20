#include <fs/vfs/proc.h>

size_t proc_pcgroup_stat(proc_handle_t *handle) {
    return 0;
}

size_t proc_pcgroup_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    const char *content = "0::/init.scope";
    int content_len = strlen(content);
    if (offset > content_len)
        return 0;
    strncpy(addr, content + offset, content_len);
    return MIN(content_len, size);
}
