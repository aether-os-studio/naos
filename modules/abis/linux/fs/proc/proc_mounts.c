#include <fs/proc/proc.h>

const char *mount_info = "";

size_t proc_mounts_stat(proc_handle_t *handle) { return strlen(mount_info); }

size_t proc_mounts_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size) {
    size_t fs_size = strlen(mount_info);
    if (offset < fs_size) {
        if (size > fs_size)
            size = fs_size;
        memcpy(addr, mount_info + offset, size);
        return size;
    } else
        return 0;
}