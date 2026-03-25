#include <fs/proc/proc.h>
#include <arch/arch.h>
#include <task/task.h>
#include <boot/boot.h>

mutex_t procfs_oplock;

vfs_node_t *cmdline = NULL;
vfs_node_t *filesystems = NULL;

ssize_t procfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *file = fd->node->handle;
    proc_handle_t *handle = (proc_handle_t *)file;
    if (!handle) {
        return -EINVAL;
    }

    return procfs_read_dispatch(handle, addr, offset, size);
}

ssize_t procfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    return size;
}

vfs_node_t *fake_procfs_root = NULL;
vfs_node_t *procfs_root = NULL;
int procfs_id = 0;
int procfs_self_id = 0;
static int mount_node_old_fsid = 0;

void procfs_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {}

bool procfs_close(vfs_node_t *node) { return false; }

int procfs_stat(vfs_node_t *node) {
    if (!node || !node->handle)
        return 0;
    proc_handle_t *handle = node->handle;
    procfs_stat_dispatch(handle, node);
    return 0;
}

ssize_t procfs_readlink(vfs_node_t *node, void *addr, size_t offset,
                        size_t size) {
    proc_handle_t *handle = node->handle;
    if (!handle)
        return -EINVAL;
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }

    if (!strcmp(handle->name, "proc_exe") && task->exec_node) {
        char *fullpath = vfs_get_fullpath_at(task->exec_node, task->fs->root);
        int len = strlen(fullpath);
        len = MIN(len, size);
        memcpy(addr, fullpath, len);
        return len;
    }
    if (!strcmp(handle->name, "proc_root")) {
        const char *fullpath = "/";
        int len = strlen(fullpath);
        len = MIN(len, size);
        memcpy(addr, fullpath, len);
        return len;
    }
    if (!strcmp(handle->name, "fd")) {
        int len = strlen(handle->content);
        len = MIN(len, size);
        memcpy(addr, handle->content, len);
        return len;
    }

    return 0;
}

int procfs_poll(vfs_node_t *node, size_t events) {
    if (!node || !node->handle)
        return 0;
    proc_handle_t *handle = node->handle;
    return procfs_poll_dispatch(handle, handle->node, events);
}

int procfs_mount(uint64_t dev, vfs_node_t *mnt) {
    if (procfs_root != fake_procfs_root)
        return -ENXIO;
    if (procfs_root == mnt)
        return -ENXIO;

    mutex_lock(&procfs_oplock);

    vfs_merge_nodes_to(mnt, fake_procfs_root);

    mount_node_old_fsid = mnt->fsid;

    procfs_root = mnt;
    mnt->fsid = procfs_id;
    mnt->dev = (PROCFS_DEV_MAJOR << 8) | 0;
    mnt->rdev = (PROCFS_DEV_MAJOR << 8) | 0;

    mutex_unlock(&procfs_oplock);

    return 0;
}

void procfs_unmount(vfs_node_t *root) {
    if (root == fake_procfs_root)
        return;

    if (root != procfs_root)
        return;

    mutex_lock(&procfs_oplock);

    vfs_merge_nodes_to(fake_procfs_root, root);

    root->fsid = mount_node_old_fsid;
    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    procfs_root = fake_procfs_root;

    root->root = root->parent ? root->parent->root : root;

    mutex_unlock(&procfs_oplock);
}

static vfs_operations_t callbacks = {
    .open = (vfs_open_t)procfs_open,
    .close = (vfs_close_t)procfs_close,
    .read = procfs_read,
    .write = (vfs_write_t)procfs_write,
    .readlink = (vfs_readlink_t)procfs_readlink,
    .stat = (vfs_stat_t)procfs_stat,
    .poll = (vfs_poll_t)procfs_poll,
    .mount = (vfs_mount_t)procfs_mount,
    .unmount = (vfs_unmount_t)procfs_unmount,

    .free_handle = vfs_generic_free_handle,
};

static void procfs_init_self_symlink(vfs_node_t *node, bool thread_self) {
    node->flags |= VFS_NODE_FLAGS_FREE_AFTER_USE;
    node->type = file_symlink;
    node->mode = 0644;
    node->fsid = procfs_self_id;

    procfs_self_handle_t *handle = calloc(1, sizeof(procfs_self_handle_t));
    node->handle = handle;
    handle->self = node;
    handle->thread_self = thread_self;
}

static void procfs_attach_task_handle(vfs_node_t *node, task_t *task,
                                      const char *handle_name) {
    proc_handle_t *handle = calloc(1, sizeof(proc_handle_t));
    node->handle = handle;
    handle->node = node;
    handle->task = task;
    snprintf(handle->name, sizeof(handle->name), "%s", handle_name);
}

static vfs_node_t *procfs_append_task_entry(vfs_node_t *parent,
                                            const char *name, file_type_t type,
                                            uint16_t mode, task_t *task,
                                            const char *handle_name) {
    vfs_node_t *node = vfs_node_alloc(parent, name);
    node->type = type;
    node->mode = mode;
    if (handle_name) {
        procfs_attach_task_handle(node, task, handle_name);
    }
    return node;
}

static void procfs_populate_task_dir(vfs_node_t *node, task_t *task) {
    procfs_append_task_entry(node, "cmdline", file_none, 0700, task,
                             "proc_cmdline");
    procfs_append_task_entry(node, "environ", file_none, 0700, task,
                             "proc_environ");
    procfs_append_task_entry(node, "maps", file_none, 0700, task, "proc_maps");
    procfs_append_task_entry(node, "root", file_symlink, 0700, task,
                             "proc_root");
    procfs_append_task_entry(node, "stat", file_none, 0700, task, "proc_stat");
    procfs_append_task_entry(node, "statm", file_none, 0700, task,
                             "proc_statm");
    procfs_append_task_entry(node, "status", file_none, 0700, task,
                             "proc_status");
    procfs_append_task_entry(node, "cgroup", file_none, 0700, task,
                             "proc_cgroup");
    procfs_append_task_entry(node, "mountinfo", file_none, 0700, task,
                             "proc_mountinfo");
    procfs_append_task_entry(node, "oom_score_adj", file_none, 0700, task,
                             "proc_oom_score_adj");
    procfs_append_task_entry(node, "exe", file_symlink, 0700, task, "proc_exe");

    vfs_node_t *fd = vfs_node_alloc(node, "fd");
    fd->type = file_dir;
    fd->mode = 0700;
}

void procfs_self_open(vfs_node_t *parent, const char *name, vfs_node_t *node) {
    procfs_self_handle_t *old_handle = node ? node->handle : NULL;
    procfs_self_handle_t *handle = malloc(sizeof(procfs_self_handle_t));
    handle->self = node;
    handle->thread_self = old_handle ? old_handle->thread_self : false;
    node->handle = handle;
    vfs_detach_child(node);
    vfs_node_t *new_self_node = vfs_node_alloc(node->parent, name);
    procfs_init_self_symlink(new_self_node, handle->thread_self);
}

bool procfs_self_close(vfs_node_t *node) {
    procfs_self_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return true;
    handle->deleted = true;
    free(handle);

    return true;
}

ssize_t procfs_self_readlink(vfs_node_t *file, void *addr, size_t offset,
                             size_t size) {
    procfs_self_handle_t *handle = file ? file->handle : NULL;
    char path[64];
    ssize_t len;

    if (handle && handle->thread_self) {
        len = snprintf(path, sizeof(path), "%llu/task/%llu",
                       (unsigned long long)task_effective_tgid(current_task),
                       (unsigned long long)current_task->pid);
    } else {
        len = snprintf(path, sizeof(path), "%llu",
                       (unsigned long long)task_effective_tgid(current_task));
    }
    len = MIN(len, (ssize_t)size);
    memcpy(addr, path, len);
    return len;
}

void procfs_self_free_handle(vfs_node_t *node) {
    procfs_self_handle_t *handle = node ? node->handle : NULL;
    free(handle);
}

static vfs_operations_t procfs_self_callbacks = {
    .open = (vfs_open_t)procfs_self_open,
    .close = (vfs_close_t)procfs_self_close,
    .readlink = (vfs_readlink_t)procfs_self_readlink,

    .free_handle = procfs_self_free_handle,
};

fs_t procfs = {
    .name = "proc",
    .magic = 0x9fa0,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

fs_t procfs_self = {
    .name = "proc_self",
    .magic = 0,
    .ops = &procfs_self_callbacks,
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_HIDDEN | FS_FLAGS_ALWAYS_OPEN,
};

int procfs_mount_point_count = 0;

void proc_init() {
    mutex_init(&procfs_oplock);

    procfs_id = vfs_regist(&procfs);
    procfs_self_id = vfs_regist(&procfs_self);

    fake_procfs_root = vfs_node_alloc(NULL, "fakeproc");
    fake_procfs_root->fsid = procfs_id;

    procfs_root = fake_procfs_root;

    vfs_node_t *self_node = vfs_node_alloc(procfs_root, "self");
    procfs_init_self_symlink(self_node, false);

    vfs_node_t *thread_self_node = vfs_node_alloc(procfs_root, "thread-self");
    procfs_init_self_symlink(thread_self_node, true);

    procfs_nodes_init();

    vfs_node_t *sys_node = vfs_node_alloc(procfs_root, "sys");
    sys_node->type = file_dir;
    sys_node->mode = 0644;
    vfs_node_t *sys_kernel_node = vfs_node_alloc(sys_node, "kernel");
    sys_kernel_node->type = file_dir;
    sys_kernel_node->mode = 0644;
    vfs_node_t *sys_kernel_osrelease_node =
        vfs_node_alloc(sys_kernel_node, "osrelease");
    sys_kernel_osrelease_node->type = file_none;
    sys_kernel_osrelease_node->mode = 0644;
    proc_handle_t *sys_kernel_osrelease_handle =
        calloc(1, sizeof(proc_handle_t));
    sys_kernel_osrelease_node->handle = sys_kernel_osrelease_handle;
    sys_kernel_osrelease_handle->node = sys_kernel_osrelease_node;
    sys_kernel_osrelease_handle->task = NULL;
    snprintf(sys_kernel_osrelease_handle->name,
             sizeof(sys_kernel_osrelease_handle->name),
             "proc_sys_kernel_osrelease");

    vfs_node_t *pressure = vfs_node_alloc(procfs_root, "pressure");
    pressure->type = file_dir;
    pressure->mode = 0644;
    vfs_node_t *pressure_memory = vfs_node_alloc(pressure, "memory");
    pressure_memory->type = file_none;
    pressure_memory->mode = 0644;
    proc_handle_t *pressure_memory_handle = calloc(1, sizeof(proc_handle_t));
    pressure_memory->handle = pressure_memory_handle;
    pressure_memory_handle->node = pressure_memory;
    pressure_memory_handle->task = NULL;
    snprintf(pressure_memory_handle->name, sizeof(pressure_memory_handle->name),
             "proc_pressure_memory");

    procfs_mount_point_count = 0;
}

void procfs_on_new_task(task_t *task) {
    if (task->pid == 0)
        return;

    char name[MAX_PID_NAME_LEN];
    sprintf(name, "%d", task->pid);

    vfs_node_t *node = vfs_node_alloc(procfs_root, name);
    node->type = file_dir;
    node->mode = 0644;
    procfs_populate_task_dir(node, task);

    node->refcount++;
    task->procfs_node = node;

    uint64_t tgid = task_effective_tgid(task);
    char tgid_name[MAX_PID_NAME_LEN];
    sprintf(tgid_name, "%d", (int)tgid);

    vfs_node_t *proc_root =
        task->pid == tgid ? node : vfs_open_at(procfs_root, tgid_name, 0);
    if (!proc_root) {
        task->procfs_thread_node = NULL;
        return;
    }

    vfs_node_t *task_root = vfs_open_at(proc_root, "task", 0);
    if (!task_root) {
        task_root = vfs_node_alloc(proc_root, "task");
        task_root->type = file_dir;
        task_root->mode = 0555;
    }

    vfs_node_t *thread_node = vfs_node_alloc(task_root, name);
    thread_node->type = file_dir;
    thread_node->mode = 0644;
    procfs_populate_task_dir(thread_node, task);

    thread_node->refcount++;
    task->procfs_thread_node = thread_node;
}

void procfs_on_open_file(task_t *task, int fd) {
    //     if (!task->procfs_node) {
    //         return;
    //     }
    //     vfs_node_t *fd_root = vfs_open_at(task->procfs_node, "fd", 0);
    //     if (!fd_root)
    //         return;

    //     if (!task->fd_info || !task->fd_info->fds[fd])
    //         return;

    //     char fd_name[8];
    //     sprintf(fd_name, "%d", fd);
    //     vfs_node_t *fd_node = vfs_node_alloc(fd_root, fd_name);
    //     fd_node->type = file_symlink;
    //     fd_node->mode = 0700;
    //     proc_handle_t *fd_node_handle = malloc(sizeof(proc_handle_t));
    //     memset(fd_node_handle, 0, sizeof(proc_handle_t));
    //     fd_node->handle = fd_node_handle;
    //     fd_node_handle->node = fd_node;
    //     fd_node_handle->task = task;
    //     vfs_node_t *node = task->fd_info->fds[fd]->node;
    //     if (node->name) {
    //         vfs_node_t *parent = node->parent;
    //         if (!parent)
    //             goto done;
    //         while (parent->parent) {
    //             parent = parent->parent;
    //         }
    //         if (parent != rootdir)
    //             goto done;
    //         char *link_name = vfs_get_fullpath_at(node, task->fs->root);
    //         strcpy(fd_node_handle->content, link_name);
    //         free(link_name);
    //     }

    // done:
    //     sprintf(fd_node_handle->name, "fd");
}

void procfs_on_close_file(task_t *task, int fd) {
    // char name[3 + 8];
    // sprintf(name, "fd/%d", fd);
    // vfs_node_t *fd_node = vfs_open_at(task->procfs_node, name, O_NOFOLLOW);
    // if (!fd_node)
    //     return;

    // vfs_free(fd_node);
}

void procfs_on_exit_task(task_t *task) {
    if (task->pid == 0)
        return;

    vfs_node_t *procfs_thread_node = task->procfs_thread_node;
    task->procfs_thread_node = NULL;
    if (procfs_thread_node) {
        vfs_free(procfs_thread_node);
    }

    vfs_node_t *procfs_node = task->procfs_node;
    task->procfs_node = NULL;
    if (procfs_node) {
        vfs_free(procfs_node);
    }
}
