#include <fs/proc.h>

size_t proc_sys_kernel_osrelease_stat(proc_handle_t *handle) {
    return strlen(BUILD_VERSION);
}

size_t proc_sys_kernel_osrelease_read(proc_handle_t *handle, void *addr,
                                      size_t offset, size_t size) {
    const char *content = BUILD_VERSION;
    size_t len = strlen(content);
    if (offset >= len) {
        return 0;
    }
    size_t to_copy = MIN(size, len - offset);
    memcpy(addr, content + offset, to_copy);
    return to_copy;
}
