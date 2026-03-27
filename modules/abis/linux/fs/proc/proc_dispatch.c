#include <fs/proc/proc.h>
#include <arch/arch.h>

proc_handle_node_t *dispatch_array[256];
static size_t dp_index = 0;
extern vfs_node_t *procfs_root;

size_t procfs_node_read(size_t len, size_t offset, size_t size, char *addr,
                        char *contect) {
    if (len == 0 || offset >= len) {
        free(contect);
        return 0;
    }
    size_t r_len = MIN(size, len - offset);
    memcpy(addr, contect + offset, r_len);
    free(contect);
    return r_len;
}

size_t procfs_task_region_read(task_t *task, uint64_t start, uint64_t end,
                               void *addr, size_t offset, size_t size) {
    if (!task || !task->mm || !addr || size == 0 || end <= start)
        return 0;

    size_t len = end - start;
    if (offset >= len)
        return 0;

    uint64_t *page_table = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t va = start + offset;
    size_t remain = MIN(size, len - offset);
    size_t copied = 0;

    while (copied < remain) {
        uint64_t page_va = PADDING_DOWN(va, PAGE_SIZE);
        uint64_t pa = translate_address(page_table, page_va);
        if (!pa)
            break;

        size_t page_off = va & (PAGE_SIZE - 1);
        size_t chunk = MIN(remain - copied, PAGE_SIZE - page_off);
        memcpy((char *)addr + copied, (void *)(phys_to_virt(pa) + page_off),
               chunk);
        va += chunk;
        copied += chunk;
    }

    return copied;
}

static uint64_t hash_dp(const char *s) {
    uint64_t h = 0;
    while (*s)
        h = h * 131 + (unsigned char)*s++;
    return h;
}

static void create_procfs_handle(char *name, read_entry_t read_entry,
                                 stat_entry_t stat_entry,
                                 readlink_entry_t readlink_entry,
                                 poll_entry_t poll_entry) {
    proc_handle_node_t *handle = malloc(sizeof(proc_handle_node_t));
    handle->name = strdup(name);
    handle->hash = hash_dp(handle->name);
    handle->read_entry = read_entry;
    handle->stat_entry = stat_entry;
    handle->readlink_entry = readlink_entry;
    handle->poll_entry = poll_entry;
    dispatch_array[dp_index++] = handle;
}

static void create_procfs_node(char *name, read_entry_t read_entry,
                               stat_entry_t stat_entry,
                               poll_entry_t poll_entry) {
    create_procfs_handle(name, read_entry, stat_entry, NULL, poll_entry);
    vfs_node_t *node = vfs_node_alloc(procfs_root, name);
    node->type = file_none;
    node->mode = 0700;
    proc_handle_t *handle0 = malloc(sizeof(proc_handle_t));
    node->handle = handle0;
    handle0->node = node;
    handle0->task = NULL;
    handle0->fd_num = -1;
    sprintf(handle0->name, "%s", name);
}

void procfs_nodes_init() {
    create_procfs_node("filesystems", proc_filesystems_read,
                       proc_filesystems_stat, NULL);
    create_procfs_node("cmdline", proc_cmdline_read, proc_cmdline_stat, NULL);
    create_procfs_node("mounts", proc_mounts_read, proc_mounts_stat, NULL);
    create_procfs_node("meminfo", proc_meminfo_read, proc_meminfo_stat, NULL);
    create_procfs_node("stat", proc_stat_read, proc_stat_stat, NULL);

    create_procfs_handle("proc_cmdline", proc_pcmdline_read, proc_pcmdline_stat,
                         NULL, NULL);
    create_procfs_handle("proc_environ", proc_penviron_read, proc_penviron_stat,
                         NULL, NULL);
    create_procfs_handle("proc_maps", proc_pmaps_read, NULL, NULL, NULL);
    create_procfs_handle("proc_stat", proc_pstat_read, proc_pstat_stat, NULL,
                         NULL);
    create_procfs_handle("proc_statm", proc_pstatm_read, proc_pstatm_stat, NULL,
                         NULL);
    create_procfs_handle("proc_status", proc_pstatus_read, proc_pstatus_stat,
                         NULL, NULL);
    create_procfs_handle("proc_cgroup", proc_pcgroup_read, proc_pcgroup_stat,
                         NULL, NULL);
    create_procfs_handle("proc_mountinfo", proc_pmountinfo_read,
                         proc_pmountinfo_stat, NULL, proc_pmountinfo_poll);
    create_procfs_handle("proc_oom_score_adj", proc_oom_score_adj_read,
                         proc_oom_score_adj_stat, NULL,
                         proc_oom_score_adj_poll);
    create_procfs_handle("proc_sys_kernel_osrelease",
                         proc_sys_kernel_osrelease_read,
                         proc_sys_kernel_osrelease_stat, NULL, NULL);
    create_procfs_handle("proc_pressure_memory", proc_pressure_memory_read,
                         proc_pressure_memory_stat, NULL, NULL);
    create_procfs_handle("proc_root", NULL, NULL, proc_root_readlink, NULL);
    create_procfs_handle("proc_exe", NULL, NULL, proc_exe_readlink, NULL);
    create_procfs_handle("proc_fd", NULL, NULL, proc_fd_readlink, NULL);
    create_procfs_handle("proc_fdinfo", proc_fdinfo_read, proc_fdinfo_stat,
                         NULL, NULL);
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

void procfs_stat_dispatch(proc_handle_t *handle, vfs_node_t *node) {
    uint64_t hash = hash_dp(handle->name);
    for (size_t i = 0; i < dp_index; i++) {
        if (hash == dispatch_array[i]->hash) {
            if (dispatch_array[i]->stat_entry)
                node->size = dispatch_array[i]->stat_entry(handle);
            return;
        }
    }
}

int procfs_poll_dispatch(proc_handle_t *handle, vfs_node_t *node, int events) {
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

ssize_t procfs_readlink_dispatch(proc_handle_t *handle, void *addr,
                                 size_t offset, size_t size) {
    uint64_t hash = hash_dp(handle->name);
    for (size_t i = 0; i < dp_index; i++) {
        if (hash == dispatch_array[i]->hash) {
            if (dispatch_array[i]->readlink_entry)
                return dispatch_array[i]->readlink_entry(handle, addr, offset,
                                                         size);
            return -EINVAL;
        }
    }
    return -ENOENT;
}
