#include <fs/proc.h>

static const char *proc_cgroups_text =
    "#subsys_name\thierarchy\tnum_cgroups\tenabled\n"
    "cpuset\t0\t1\t1\n"
    "cpu\t0\t1\t1\n"
    "cpuacct\t0\t1\t1\n"
    "blkio\t0\t1\t1\n"
    "memory\t0\t1\t1\n"
    "devices\t0\t1\t1\n"
    "freezer\t0\t1\t1\n"
    "net_cls\t0\t1\t1\n"
    "perf_event\t0\t1\t1\n"
    "net_prio\t0\t1\t1\n"
    "hugetlb\t0\t1\t1\n"
    "pids\t0\t1\t1\n"
    "rdma\t0\t1\t1\n";

size_t proc_cgroups_stat(proc_handle_t *handle) {
    (void)handle;
    return strlen(proc_cgroups_text);
}

size_t proc_cgroups_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    size_t len = strlen(proc_cgroups_text);

    (void)handle;
    if (offset >= len)
        return 0;

    size_t to_copy = MIN(size, len - offset);
    memcpy(addr, proc_cgroups_text + offset, to_copy);
    return to_copy;
}
