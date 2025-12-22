#include <fs/vfs/proc.h>

size_t proc_sys_kernel_osrelease_stat(proc_handle_t *handle) {
    return sizeof(BUILD_VERSION);
}

size_t proc_sys_kernel_osrelease_read(proc_handle_t *handle, void *addr,
                                      size_t offset, size_t size) {
    const char *content = BUILD_VERSION;
    uint64_t len = sizeof(BUILD_VERSION);
    if (offset > len) {
        return 0;
    }
    len = MIN(len, offset + size);
    size_t to_copy = MIN(len, size);
    memcpy(addr, content + offset, to_copy);
    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}
