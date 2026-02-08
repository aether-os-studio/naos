#include <fs/vfs/proc/proc.h>

proc_handle_node_t *dispatch_array[256];
static size_t dp_index = 0;
extern vfs_node_t procfs_root;

size_t procfs_node_read(size_t len, size_t offset, size_t size, char *addr,
                        char *contect) {
    if (len == 0 || offset >= len) {
        free(contect);
        return 0;
    }
    size_t r_len = MIN(size, len);
    memcpy(addr, contect, r_len);
    free(contect);
    return r_len;
}

static uint64_t hash_dp(const char *s) {
    uint64_t h = 0;
    while (*s)
        h = h * 131 + (unsigned char)*s++;
    return h;
}

static void create_procfs_handle(char *name, read_entry_t read_entry,
                                 stat_entry_t stat_entry,
                                 poll_entry_t poll_entry) {
    proc_handle_node_t *handle = malloc(sizeof(proc_handle_node_t));
    handle->name = strdup(name);
    handle->hash = hash_dp(handle->name);
    handle->read_entry = read_entry;
    handle->stat_entry = stat_entry;
    handle->poll_entry = poll_entry;
    dispatch_array[dp_index++] = handle;
}

static void create_procfs_node(char *name, read_entry_t read_entry,
                               stat_entry_t stat_entry,
                               poll_entry_t poll_entry) {
    create_procfs_handle(name, read_entry, stat_entry, poll_entry);
    vfs_node_t node = vfs_node_alloc(procfs_root, name);
    node->type = file_none;
    node->mode = 0700;
    proc_handle_t *handle0 = malloc(sizeof(proc_handle_t));
    node->handle = handle0;
    handle0->node = node;
    handle0->task = NULL;
    sprintf(handle0->name, "%s", name);
}

void procfs_nodes_init() {
    create_procfs_node("filesystems", proc_filesystems_read,
                       proc_filesystems_stat, NULL);
    create_procfs_node("cmdline", proc_cmdline_read, proc_cmdline_stat, NULL);
    create_procfs_node("mounts", proc_mounts_read, proc_mounts_stat, NULL);
    create_procfs_node("meminfo", proc_meminfo_read, proc_meminfo_stat, NULL);

    create_procfs_handle("proc_cmdline", proc_pcmdline_read, proc_pcmdline_stat,
                         NULL);
    create_procfs_handle("proc_maps", proc_pmaps_read, NULL, NULL);
    create_procfs_handle("proc_stat", proc_pstat_read, proc_pstat_stat, NULL);
    create_procfs_handle("proc_status", proc_pstatus_read, proc_pstatus_stat,
                         NULL);
    create_procfs_handle("proc_cgroup", proc_pcgroup_read, proc_pcgroup_stat,
                         NULL);
    create_procfs_handle("proc_mountinfo", proc_pmountinfo_read,
                         proc_pmountinfo_stat, proc_pmountinfo_poll);
    create_procfs_handle("proc_oom_score_adj", proc_oom_score_adj_read,
                         proc_oom_score_adj_stat, proc_oom_score_adj_poll);
    create_procfs_handle("proc_sys_kernel_osrelease",
                         proc_sys_kernel_osrelease_read,
                         proc_sys_kernel_osrelease_stat, NULL);
}

size_t procfs_read_dispatch(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size) {
    uint64_t hash = hash_dp(handle->name);
    for (size_t i = 0; i < dp_index; i++) {
        if (hash == dispatch_array[i]->hash) {
            if (dispatch_array[i]->read_entry)
                return dispatch_array[i]->read_entry(handle, addr, offset,
                                                     size);
        }
    }
    return (size_t)-ENOENT;
}

void procfs_stat_dispatch(proc_handle_t *handle, vfs_node_t node) {
    uint64_t hash = hash_dp(handle->name);
    for (size_t i = 0; i < dp_index; i++) {
        if (hash == dispatch_array[i]->hash) {
            if (dispatch_array[i]->stat_entry)
                node->size = dispatch_array[i]->stat_entry(handle);
            return;
        }
    }
}

int procfs_poll_dispatch(proc_handle_t *handle, vfs_node_t node, int events) {
    uint64_t hash = hash_dp(handle->name);
    for (size_t i = 0; i < dp_index; i++) {
        if (hash == dispatch_array[i]->hash) {
            if (dispatch_array[i]->poll_entry)
                return dispatch_array[i]->poll_entry(handle, events);
            return 0;
        }
    }
    return 0;
}
