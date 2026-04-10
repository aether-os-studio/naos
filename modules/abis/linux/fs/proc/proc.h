#pragma once

#include <fs/vfs/vfs.h>
#include <task/task.h>

#define MAX_PID_NAME_LEN 8

struct task;
typedef struct task task_t;

typedef struct proc_handle proc_handle_t;

typedef size_t (*stat_entry_t)(proc_handle_t *handle);
typedef int (*poll_entry_t)(proc_handle_t *handle, int events);
typedef size_t (*read_entry_t)(proc_handle_t *handle, void *addr, size_t offset,
                               size_t size);
typedef ssize_t (*write_entry_t)(proc_handle_t *handle, const void *addr,
                                 size_t offset, size_t size);
typedef ssize_t (*readlink_entry_t)(proc_handle_t *handle, void *addr,
                                    size_t offset, size_t size);

struct proc_handle {
    char name[64];
    char content[256];
    vfs_node_t *node;
    uint64_t task_pid;
    int fd_num;
};

static inline task_t *procfs_handle_task(proc_handle_t *handle) {
    if (!handle || handle->task_pid == 0)
        return NULL;

    return task_find_by_pid(handle->task_pid);
}

static inline task_t *procfs_handle_task_or_current(proc_handle_t *handle) {
    task_t *task = procfs_handle_task(handle);
    return task ? task : current_task;
}

typedef struct proc_handle_node {
    char *name;
    uint64_t hash;
    read_entry_t read_entry;
    write_entry_t write_entry;
    stat_entry_t stat_entry;
    readlink_entry_t readlink_entry;
    poll_entry_t poll_entry;
} proc_handle_node_t;

typedef struct procfs_self_handle {
    vfs_node_t *self;
    bool deleted;
    bool thread_self;
} procfs_self_handle_t;

void procfs_nodes_init();
void procfs_stat_dispatch(proc_handle_t *handle, vfs_node_t *node);
int procfs_poll_dispatch(proc_handle_t *handle, vfs_node_t *node, int events);
size_t procfs_read_dispatch(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size);
ssize_t procfs_write_dispatch(proc_handle_t *handle, const void *addr,
                              size_t offset, size_t size);
ssize_t procfs_readlink_dispatch(proc_handle_t *handle, void *addr,
                                 size_t offset, size_t size);

size_t proc_filesystems_stat(proc_handle_t *handle);
size_t proc_filesystems_read(proc_handle_t *handle, void *addr, size_t offset,
                             size_t size);

size_t proc_cmdline_stat(proc_handle_t *handle);
size_t proc_cmdline_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size);
size_t proc_mounts_stat(proc_handle_t *handle);
size_t proc_mounts_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size);
size_t proc_pcmdline_stat(proc_handle_t *handle);
size_t proc_pcmdline_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size);
size_t proc_penviron_stat(proc_handle_t *handle);
size_t proc_penviron_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size);
size_t proc_pmaps_stat(proc_handle_t *handle);
size_t proc_pmaps_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size);
size_t proc_pstat_stat(proc_handle_t *handle);
size_t proc_pstat_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size);
size_t proc_pstatm_stat(proc_handle_t *handle);
size_t proc_pstatm_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size);
size_t proc_pstatus_stat(proc_handle_t *handle);
size_t proc_pstatus_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size);
size_t proc_pcgroup_stat(proc_handle_t *handle);
size_t proc_pcgroup_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size);
size_t proc_meminfo_stat(proc_handle_t *handle);
size_t proc_meminfo_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size);
size_t proc_stat_stat(proc_handle_t *handle);
size_t proc_stat_read(proc_handle_t *handle, void *addr, size_t offset,
                      size_t size);
size_t proc_sys_kernel_osrelease_stat(proc_handle_t *handle);
size_t proc_sys_kernel_osrelease_read(proc_handle_t *handle, void *addr,
                                      size_t offset, size_t size);
size_t proc_sys_kernel_hostname_stat(proc_handle_t *handle);
size_t proc_sys_kernel_hostname_read(proc_handle_t *handle, void *addr,
                                     size_t offset, size_t size);
ssize_t proc_sys_kernel_hostname_write(proc_handle_t *handle, const void *addr,
                                       size_t offset, size_t size);
size_t proc_sys_kernel_domainname_stat(proc_handle_t *handle);
size_t proc_sys_kernel_domainname_read(proc_handle_t *handle, void *addr,
                                       size_t offset, size_t size);
ssize_t proc_sys_kernel_domainname_write(proc_handle_t *handle,
                                         const void *addr, size_t offset,
                                         size_t size);
size_t proc_pressure_memory_stat(proc_handle_t *handle);
size_t proc_pressure_memory_read(proc_handle_t *handle, void *addr,
                                 size_t offset, size_t size);
char *procfs_generate_mount_table(task_t *task, bool mountinfo,
                                  size_t *content_len);
size_t proc_pmountinfo_stat(proc_handle_t *handle);
size_t proc_pmountinfo_stat(proc_handle_t *handle);
int proc_pmountinfo_poll(proc_handle_t *handle, int events);
size_t proc_pmountinfo_read(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size);
size_t proc_puid_map_stat(proc_handle_t *handle);
size_t proc_puid_map_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size);
ssize_t proc_puid_map_write(proc_handle_t *handle, const void *addr,
                            size_t offset, size_t size);
size_t proc_pgid_map_stat(proc_handle_t *handle);
size_t proc_pgid_map_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size);
ssize_t proc_pgid_map_write(proc_handle_t *handle, const void *addr,
                            size_t offset, size_t size);
size_t proc_psetgroups_stat(proc_handle_t *handle);
size_t proc_psetgroups_read(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size);
ssize_t proc_psetgroups_write(proc_handle_t *handle, const void *addr,
                              size_t offset, size_t size);
ssize_t proc_oom_score_adj_write(proc_handle_t *handle, const void *addr,
                                 size_t offset, size_t size);
size_t proc_oom_score_adj_stat(proc_handle_t *handle);
int proc_oom_score_adj_poll(proc_handle_t *handle, int events);
size_t proc_oom_score_adj_read(proc_handle_t *handle, void *addr, size_t offset,
                               size_t size);
ssize_t proc_root_readlink(proc_handle_t *handle, void *addr, size_t offset,
                           size_t size);
ssize_t proc_exe_readlink(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size);
ssize_t proc_fd_readlink(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size);
size_t proc_fdinfo_stat(proc_handle_t *handle);
size_t proc_fdinfo_read(proc_handle_t *handle, void *addr, size_t offset,
                        size_t size);
size_t procfs_node_read(size_t len, size_t offset, size_t size, char *addr,
                        char *contect);
size_t procfs_task_region_read(task_t *task, uint64_t start, uint64_t end,
                               void *addr, size_t offset, size_t size);

void procfs_on_new_task(task_t *task);
void procfs_on_open_file(task_t *task, int fd);
void procfs_on_close_file(task_t *task, int fd);
void procfs_on_exit_task(task_t *task);
void proc_init();
