#include <fs/proc.h>

static const char *proc_filesystems_text = "nodev\tproc\n"
                                           "nodev\tsysfs\n"
                                           "nodev\ttmpfs\n"
                                           "nodev\tdevtmpfs\n"
                                           "nodev\tramfs\n"
                                           "nodev\tconfigfs\n"
                                           "nodev\tcgroup2\n"
                                           "nodev\tsockfs\n"
                                           "nodev\tnotifyfs\n";

size_t proc_filesystems_stat(proc_handle_t *handle) {
    (void)handle;
    return strlen(proc_filesystems_text);
}

size_t proc_filesystems_read(proc_handle_t *handle, void *addr, size_t offset,
                             size_t size) {
    (void)handle;

    size_t fs_size = strlen(proc_filesystems_text);
    if (offset >= fs_size)
        return 0;
    size_t to_copy = MIN(size, fs_size - offset);
    memcpy(addr, proc_filesystems_text + offset, to_copy);
    return to_copy;
}
