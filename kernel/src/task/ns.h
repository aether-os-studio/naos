#pragma once

#include <fs/vfs/vfs.h>
#include <libs/klibc.h>
#include <libs/llist.h>

struct task;
typedef struct task task_t;

typedef struct task_fs {
    int ref_count;
    struct vfs_process_fs vfs;
    uint16_t umask;
} task_fs_t;

typedef struct task_ns_common {
    int ref_count;
    uint64_t inum;
} task_ns_common_t;

typedef struct task_uts_namespace {
    task_ns_common_t common;
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
} task_uts_namespace_t;

typedef struct task_mount_namespace {
    task_ns_common_t common;
    struct vfs_mount *tree_root;
    struct vfs_mount *root;
    uint64_t seq;
    bool owns_tree;
} task_mount_namespace_t;

#define TASK_USERNS_MAX_ID_MAPS 8

typedef struct task_id_map_range {
    uint32_t inside_id;
    uint32_t outside_id;
    uint32_t length;
} task_id_map_range_t;

typedef enum task_userns_setgroups_state {
    TASK_USERNS_SETGROUPS_ALLOW = 0,
    TASK_USERNS_SETGROUPS_DENY = 1,
} task_userns_setgroups_state_t;

typedef struct task_user_namespace {
    task_ns_common_t common;
    uint32_t level;
    int64_t owner_uid;
    int64_t owner_gid;
    mutex_t lock;
    task_id_map_range_t uid_map[TASK_USERNS_MAX_ID_MAPS];
    task_id_map_range_t gid_map[TASK_USERNS_MAX_ID_MAPS];
    size_t uid_map_count;
    size_t gid_map_count;
    bool uid_map_written;
    bool gid_map_written;
    task_userns_setgroups_state_t setgroups_state;
} task_user_namespace_t;

typedef struct task_simple_namespace {
    task_ns_common_t common;
} task_simple_namespace_t;

typedef struct task_ns_proxy {
    int ref_count;
    task_uts_namespace_t *uts_ns;
    task_mount_namespace_t *mnt_ns;
    task_user_namespace_t *user_ns;
    task_simple_namespace_t *pid_ns;
    task_simple_namespace_t *net_ns;
    task_simple_namespace_t *ipc_ns;
    task_simple_namespace_t *cgroup_ns;
} task_ns_proxy_t;

task_fs_t *task_fs_create(const struct vfs_path *root,
                          const struct vfs_path *pwd);
task_fs_t *task_fs_clone(task_t *task, uint64_t clone_flags);
void task_fs_get(task_fs_t *fs);
void task_fs_put(task_fs_t *fs);
int task_fs_chdir(task_t *task, const struct vfs_path *pwd);
int task_fs_chroot(task_t *task, const struct vfs_path *root);

task_ns_proxy_t *task_ns_proxy_create_initial(void);
task_ns_proxy_t *task_ns_proxy_clone(task_t *task, uint64_t clone_flags);
void task_ns_proxy_get(task_ns_proxy_t *nsproxy);
void task_ns_proxy_put(task_ns_proxy_t *nsproxy);

struct vfs_mount *task_mount_namespace_root(task_t *task);
int task_mount_namespace_set_root(task_t *task, struct vfs_mount *root);
task_user_namespace_t *task_user_namespace_of_task(task_t *task);
