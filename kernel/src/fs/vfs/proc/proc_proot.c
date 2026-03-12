#include <fs/vfs/proc/proc.h>
#include <boot/boot.h>

size_t proc_proot_stat(proc_handle_t *handle) { return 1; }

size_t proc_proot_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size) {
    if (addr && size >= 1)
        strcpy(addr, "/");
    return 1;
}
