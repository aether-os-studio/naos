#include <fs/vfs/proc/proc.h>
#include <boot/boot.h>

size_t proc_cmdline_stat(proc_handle_t *handle) {
    return strlen(boot_get_cmdline());
}

size_t proc_cmdline_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    size_t fs_size = strlen(boot_get_cmdline());
    if (offset < fs_size) {
        if (size > fs_size)
            size = fs_size;
        memcpy(addr, boot_get_cmdline() + offset, size);
        return size;
    } else
        return 0;
}
