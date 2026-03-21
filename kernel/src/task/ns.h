#pragma once

#include <libs/klibc.h>
#include <libs/llist.h>

struct task;
typedef struct task task_t;

struct vfs_node;
typedef struct vfs_node vfs_node_t;
struct fs;
struct mount_point;

typedef struct task_fs {
    int ref_count;
    vfs_node_t *root;
    vfs_node_t *cwd;
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
    vfs_node_t *root;
    struct llist_header mount_points;
} task_mount_namespace_t;

typedef struct task_user_namespace {
    task_ns_common_t common;
    uint32_t level;
    int64_t owner_uid;
    int64_t owner_gid;
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

task_fs_t *task_fs_create(vfs_node_t *root, vfs_node_t *cwd);
task_fs_t *task_fs_clone(task_t *task, uint64_t clone_flags);
void task_fs_get(task_fs_t *fs);
void task_fs_put(task_fs_t *fs);
int task_fs_chdir(task_t *task, vfs_node_t *cwd);
int task_fs_chroot(task_t *task, vfs_node_t *root);

void task_mnt_namespace_add_mount(task_mount_namespace_t *mnt_ns, struct fs *fs,
                                  vfs_node_t *dir, vfs_node_t *root_node,
                                  const char *devname);
void task_mnt_namespace_remove_mount(task_mount_namespace_t *mnt_ns,
                                     vfs_node_t *dir);
int task_mnt_namespace_move_mount(task_mount_namespace_t *mnt_ns,
                                  vfs_node_t *old_dir, vfs_node_t *new_dir);
struct mount_point *
task_mnt_namespace_find_mount(task_mount_namespace_t *mnt_ns, vfs_node_t *dir);
struct mount_point *
task_mnt_namespace_find_mount_by_root(task_mount_namespace_t *mnt_ns,
                                      vfs_node_t *root_node);

task_ns_proxy_t *task_ns_proxy_create_initial(void);
task_ns_proxy_t *task_ns_proxy_clone(task_t *task, uint64_t clone_flags);
void task_ns_proxy_get(task_ns_proxy_t *nsproxy);
void task_ns_proxy_put(task_ns_proxy_t *nsproxy);
