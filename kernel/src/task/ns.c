#include <task/ns.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <init/abis.h>

extern struct llist_header mount_points;

static uint64_t next_namespace_inum = 1;

static uint64_t task_ns_alloc_inum(void) {
    return __atomic_fetch_add(&next_namespace_inum, 1, __ATOMIC_RELAXED);
}

static void task_ns_common_init(task_ns_common_t *common) {
    if (!common)
        return;

    common->ref_count = 1;
    common->inum = task_ns_alloc_inum();
}

task_fs_t *task_fs_create(vfs_node_t *root, vfs_node_t *cwd) {
    if (!root)
        return NULL;
    if (!cwd)
        cwd = root;

    task_fs_t *fs = calloc(1, sizeof(task_fs_t));
    if (!fs)
        return NULL;

    fs->ref_count = 1;
    fs->root = root;
    fs->cwd = cwd;
    fs->umask = 0022;

    vfs_node_ref_get(root);
    if (cwd == root) {
        vfs_node_ref_get(root);
    } else {
        vfs_node_ref_get(cwd);
    }

    return fs;
}

void task_fs_get(task_fs_t *fs) {
    if (!fs)
        return;
    __atomic_add_fetch(&fs->ref_count, 1, __ATOMIC_RELAXED);
}

void task_fs_put(task_fs_t *fs) {
    if (!fs)
        return;

    if (__atomic_sub_fetch(&fs->ref_count, 1, __ATOMIC_ACQ_REL) == 0) {
        vfs_close(fs->cwd);
        vfs_close(fs->root);
        free(fs);
    }
}

task_fs_t *task_fs_clone(task_t *task, uint64_t clone_flags) {
    if (!task || !task->fs)
        return NULL;

    task_fs_t *parent_fs = task->fs;
    if (clone_flags & CLONE_FS) {
        task_fs_get(parent_fs);
        return parent_fs;
    }

    task_fs_t *child_fs = task_fs_create(parent_fs->root, parent_fs->cwd);
    if (!child_fs)
        return NULL;

    child_fs->umask = parent_fs->umask;
    return child_fs;
}

int task_fs_chdir(task_t *task, vfs_node_t *cwd) {
    if (!task || !task->fs || !cwd)
        return -EINVAL;
    if (!vfs_is_ancestor(task->fs->root, cwd))
        return -EPERM;

    vfs_node_ref_get(cwd);
    vfs_close(task->fs->cwd);
    task->fs->cwd = cwd;
    return 0;
}

int task_fs_chroot(task_t *task, vfs_node_t *root) {
    if (!task || !task->fs || !root)
        return -EINVAL;

    vfs_node_ref_get(root);
    vfs_close(task->fs->root);
    task->fs->root = root;

    if (!task->fs->cwd) {
        vfs_node_ref_get(root);
        task->fs->cwd = root;
    }

    return 0;
}

static task_uts_namespace_t *
task_uts_namespace_create(const task_uts_namespace_t *parent) {
    task_uts_namespace_t *uts_ns = calloc(1, sizeof(*uts_ns));
    if (!uts_ns)
        return NULL;

    task_ns_common_init(&uts_ns->common);
    if (parent) {
        memcpy(uts_ns, parent, sizeof(*uts_ns));
        task_ns_common_init(&uts_ns->common);
        return uts_ns;
    }

    strcpy(uts_ns->sysname, "NeoAetherOS");
    strcpy(uts_ns->nodename, "aether");
    strcpy(uts_ns->release, BUILD_VERSION);
    strcpy(uts_ns->version, BUILD_VERSION);
#if defined(__x86_64__)
    strcpy(uts_ns->machine, "x86_64");
#elif defined(__aarch64__)
    strcpy(uts_ns->machine, "aarch64");
#elif defined(__riscv64)
    strcpy(uts_ns->machine, "riscv64");
#elif defined(__loongarch64__)
    strcpy(uts_ns->machine, "loongarch64");
#else
    strcpy(uts_ns->machine, "unknown");
#endif
    uts_ns->domainname[0] = '\0';
    return uts_ns;
}

static task_mount_namespace_t *
task_mount_namespace_create(vfs_node_t *root,
                            const task_mount_namespace_t *parent) {
    if (!root)
        return NULL;

    task_mount_namespace_t *mnt_ns = calloc(1, sizeof(*mnt_ns));
    if (!mnt_ns)
        return NULL;

    task_ns_common_init(&mnt_ns->common);
    if (parent) {
        mnt_ns->common.inum = task_ns_alloc_inum();
    }
    mnt_ns->root = root;
    llist_init_head(&mnt_ns->mount_points);
    vfs_node_ref_get(root);

    if (parent) {
        size_t count = 0;
        struct mount_point *mnt = NULL, *tmp = NULL;
        llist_for_each(mnt, tmp, &parent->mount_points, node) { count++; }

        struct mount_point **mounts = calloc(count, sizeof(*mounts));
        if (!mounts) {
            vfs_close(mnt_ns->root);
            free(mnt_ns);
            return NULL;
        }

        size_t idx = 0;
        llist_for_each(mnt, tmp, &parent->mount_points, node) {
            mounts[idx++] = mnt;
        }

        while (idx > 0) {
            mnt = mounts[--idx];
            task_mnt_namespace_add_mount(mnt_ns, mnt->fs, mnt->dir,
                                         mnt->root_node, mnt->devname);
        }

        free(mounts);
    }
    return mnt_ns;
}

static task_user_namespace_t *
task_user_namespace_create(const task_user_namespace_t *parent, task_t *owner) {
    task_user_namespace_t *user_ns = calloc(1, sizeof(*user_ns));
    if (!user_ns)
        return NULL;

    task_ns_common_init(&user_ns->common);
    if (parent) {
        user_ns->level = parent->level + 1;
        if (owner) {
            user_ns->owner_uid = owner->euid;
            user_ns->owner_gid = owner->egid;
        } else {
            user_ns->owner_uid = parent->owner_uid;
            user_ns->owner_gid = parent->owner_gid;
        }
    } else if (owner) {
        user_ns->owner_uid = owner->euid;
        user_ns->owner_gid = owner->egid;
    }

    return user_ns;
}

static task_simple_namespace_t *
task_simple_namespace_create(const task_simple_namespace_t *parent) {
    task_simple_namespace_t *ns = calloc(1, sizeof(*ns));
    if (!ns)
        return NULL;

    task_ns_common_init(&ns->common);
    (void)parent;
    return ns;
}

static void task_ns_common_get(task_ns_common_t *common) {
    if (!common)
        return;
    __atomic_add_fetch(&common->ref_count, 1, __ATOMIC_RELAXED);
}

static bool task_ns_common_put(task_ns_common_t *common) {
    if (!common)
        return false;
    return __atomic_sub_fetch(&common->ref_count, 1, __ATOMIC_ACQ_REL) == 0;
}

static void task_uts_namespace_put(task_uts_namespace_t *uts_ns) {
    if (task_ns_common_put(&uts_ns->common))
        free(uts_ns);
}

static void task_mount_namespace_put(task_mount_namespace_t *mnt_ns) {
    if (!mnt_ns)
        return;
    if (task_ns_common_put(&mnt_ns->common)) {
        struct mount_point *mnt = NULL, *tmp = NULL;
        llist_for_each(mnt, tmp, &mnt_ns->mount_points, node) {
            llist_delete(&mnt->node);
            free(mnt->devname);
            free(mnt);
        }
        vfs_close(mnt_ns->root);
        free(mnt_ns);
    }
}

struct mount_point *
task_mnt_namespace_find_mount(task_mount_namespace_t *mnt_ns, vfs_node_t *dir) {
    if (!mnt_ns || !dir)
        return NULL;

    struct mount_point *mnt = NULL, *tmp = NULL;
    llist_for_each(mnt, tmp, &mnt_ns->mount_points, node) {
        if (mnt->dir == dir)
            return mnt;
    }
    return NULL;
}

struct mount_point *
task_mnt_namespace_find_mount_by_root(task_mount_namespace_t *mnt_ns,
                                      vfs_node_t *root_node) {
    if (!mnt_ns || !root_node)
        return NULL;

    struct mount_point *mnt = NULL, *tmp = NULL;
    llist_for_each(mnt, tmp, &mnt_ns->mount_points, node) {
        if (mnt->root_node == root_node)
            return mnt;
    }
    return NULL;
}

void task_mnt_namespace_add_mount(task_mount_namespace_t *mnt_ns, struct fs *fs,
                                  vfs_node_t *dir, vfs_node_t *root_node,
                                  const char *devname) {
    if (!mnt_ns || !fs || !dir || !root_node || !devname)
        return;

    if (root_node != dir && vfs_bind_mount_root(root_node, dir) < 0)
        return;

    struct mount_point *mnt = calloc(1, sizeof(struct mount_point));
    if (!mnt)
        return;

    mnt->fs = fs;
    mnt->dir = dir;
    mnt->root_node = root_node;
    mnt->original_dir_root = dir->root;
    vfs_node_ref_get(dir);
    vfs_node_ref_get(root_node);
    mnt->devname = strdup(devname);
    llist_init_head(&mnt->node);
    llist_prepend(&mnt_ns->mount_points, &mnt->node);
}

void task_mnt_namespace_remove_mount(task_mount_namespace_t *mnt_ns,
                                     vfs_node_t *dir) {
    struct mount_point *mnt =
        task_mnt_namespace_find_mount_by_root(mnt_ns, dir);
    if (!mnt)
        mnt = task_mnt_namespace_find_mount(mnt_ns, dir);
    if (!mnt)
        return;

    llist_delete(&mnt->node);
    vfs_close(mnt->dir);
    if (mnt->root_node != mnt->dir) {
        vfs_free(mnt->root_node);
    } else {
        vfs_close(mnt->root_node);
    }
    free(mnt->devname);
    free(mnt);
}

int task_mnt_namespace_move_mount(task_mount_namespace_t *mnt_ns,
                                  vfs_node_t *old_dir, vfs_node_t *new_dir) {
    struct mount_point *mnt =
        task_mnt_namespace_find_mount_by_root(mnt_ns, old_dir);
    if (!mnt)
        mnt = task_mnt_namespace_find_mount(mnt_ns, old_dir);
    if (!mnt)
        return -ENOENT;

    if (!(new_dir->type & file_dir))
        return -ENOTDIR;

    if (vfs_is_ancestor(mnt->root_node, new_dir))
        return -EINVAL;

    if (mnt->root_node != mnt->dir &&
        vfs_bind_mount_root(mnt->root_node, new_dir) < 0) {
        return -ENOMEM;
    }

    vfs_node_ref_get(new_dir);
    vfs_close(mnt->dir);
    mnt->dir = new_dir;
    mnt->original_dir_root = new_dir->root;

    return 0;
}

static void task_user_namespace_put(task_user_namespace_t *user_ns) {
    if (task_ns_common_put(&user_ns->common))
        free(user_ns);
}

static void task_simple_namespace_put(task_simple_namespace_t *ns) {
    if (task_ns_common_put(&ns->common))
        free(ns);
}

task_ns_proxy_t *task_ns_proxy_create_initial(void) {
    task_ns_proxy_t *nsproxy = calloc(1, sizeof(task_ns_proxy_t));
    if (!nsproxy)
        return NULL;

    nsproxy->ref_count = 1;
    nsproxy->uts_ns = task_uts_namespace_create(NULL);
    nsproxy->mnt_ns = task_mount_namespace_create(rootdir, NULL);
    nsproxy->user_ns = task_user_namespace_create(NULL, NULL);
    nsproxy->pid_ns = task_simple_namespace_create(NULL);
    nsproxy->net_ns = task_simple_namespace_create(NULL);
    nsproxy->ipc_ns = task_simple_namespace_create(NULL);
    nsproxy->cgroup_ns = task_simple_namespace_create(NULL);

    if (!nsproxy->uts_ns || !nsproxy->mnt_ns || !nsproxy->user_ns ||
        !nsproxy->pid_ns || !nsproxy->net_ns || !nsproxy->ipc_ns ||
        !nsproxy->cgroup_ns) {
        task_ns_proxy_put(nsproxy);
        return NULL;
    }

    size_t count = 0;
    struct mount_point *mnt = NULL, *tmp = NULL;
    llist_for_each(mnt, tmp, &mount_points, node) { count++; }

    struct mount_point **mounts = calloc(count, sizeof(*mounts));
    if (!mounts)
        return nsproxy;

    size_t idx = 0;
    llist_for_each(mnt, tmp, &mount_points, node) { mounts[idx++] = mnt; }

    while (idx > 0) {
        mnt = mounts[--idx];
        task_mnt_namespace_add_mount(nsproxy->mnt_ns, mnt->fs, mnt->dir,
                                     mnt->root_node ? mnt->root_node : mnt->dir,
                                     mnt->devname);
    }

    free(mounts);

    return nsproxy;
}

void task_ns_proxy_get(task_ns_proxy_t *nsproxy) {
    if (!nsproxy)
        return;
    __atomic_add_fetch(&nsproxy->ref_count, 1, __ATOMIC_RELAXED);
}

void task_ns_proxy_put(task_ns_proxy_t *nsproxy) {
    if (!nsproxy)
        return;

    if (__atomic_sub_fetch(&nsproxy->ref_count, 1, __ATOMIC_ACQ_REL) != 0)
        return;

    task_uts_namespace_put(nsproxy->uts_ns);
    task_mount_namespace_put(nsproxy->mnt_ns);
    task_user_namespace_put(nsproxy->user_ns);
    task_simple_namespace_put(nsproxy->pid_ns);
    task_simple_namespace_put(nsproxy->net_ns);
    task_simple_namespace_put(nsproxy->ipc_ns);
    task_simple_namespace_put(nsproxy->cgroup_ns);
    free(nsproxy);
}

task_ns_proxy_t *task_ns_proxy_clone(task_t *task, uint64_t clone_flags) {
    if (!task || !task->nsproxy)
        return NULL;

    task_ns_proxy_t *parent = task->nsproxy;
    task_ns_proxy_t *child = calloc(1, sizeof(task_ns_proxy_t));
    if (!child)
        return NULL;

    child->ref_count = 1;

    if (clone_flags & CLONE_NEWUTS) {
        child->uts_ns = task_uts_namespace_create(parent->uts_ns);
    } else {
        child->uts_ns = parent->uts_ns;
        task_ns_common_get(&child->uts_ns->common);
    }

    if (clone_flags & CLONE_NEWNS) {
        vfs_node_t *root = task->fs ? task->fs->root : rootdir;
        child->mnt_ns = task_mount_namespace_create(root, parent->mnt_ns);
    } else {
        child->mnt_ns = parent->mnt_ns;
        task_ns_common_get(&child->mnt_ns->common);
    }

    if (clone_flags & CLONE_NEWUSER) {
        child->user_ns = task_user_namespace_create(parent->user_ns, task);
    } else {
        child->user_ns = parent->user_ns;
        task_ns_common_get(&child->user_ns->common);
    }

    if (clone_flags & CLONE_NEWPID) {
        child->pid_ns = task_simple_namespace_create(parent->pid_ns);
    } else {
        child->pid_ns = parent->pid_ns;
        task_ns_common_get(&child->pid_ns->common);
    }

    if (clone_flags & CLONE_NEWNET) {
        child->net_ns = task_simple_namespace_create(parent->net_ns);
    } else {
        child->net_ns = parent->net_ns;
        task_ns_common_get(&child->net_ns->common);
    }

    if (clone_flags & CLONE_NEWIPC) {
        child->ipc_ns = task_simple_namespace_create(parent->ipc_ns);
    } else {
        child->ipc_ns = parent->ipc_ns;
        task_ns_common_get(&child->ipc_ns->common);
    }

    if (clone_flags & CLONE_NEWCGROUP) {
        child->cgroup_ns = task_simple_namespace_create(parent->cgroup_ns);
    } else {
        child->cgroup_ns = parent->cgroup_ns;
        task_ns_common_get(&child->cgroup_ns->common);
    }

    if (!child->uts_ns || !child->mnt_ns || !child->user_ns || !child->pid_ns ||
        !child->net_ns || !child->ipc_ns || !child->cgroup_ns) {
        task_ns_proxy_put(child);
        return NULL;
    }

    return child;
}
