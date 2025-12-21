#include <fs/vfs/proc/proc.h>
#include <arch/arch.h>
#include <task/task.h>
#include <boot/boot.h>

spinlock_t procfs_oplock = SPIN_INIT;

vfs_node_t cmdline = NULL;
vfs_node_t filesystems = NULL;

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

vfs_node_t fake_procfs_root = NULL;
vfs_node_t procfs_root = NULL;
int procfs_id = 0;
int procfs_self_id = 0;
static int mount_node_old_fsid = 0;

static int dummy() { return -ENOSYS; }

void procfs_open(void *parent, const char *name, vfs_node_t node) {}

bool procfs_close(void *current) { return false; }

int procfs_stat(void *file, vfs_node_t node) {
    if (file == NULL)
        return 0;
    proc_handle_t *handle = file;
    procfs_stat_dispatch(handle, node);
    return 0;
}

ssize_t procfs_readlink(vfs_node_t node, void *addr, size_t offset,
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

    if (!strcmp(handle->name, "exe") && task->exec_node) {
        char *fullpath = vfs_get_fullpath(task->exec_node);
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

int procfs_poll(void *file, size_t events) {
    if (file == NULL)
        return 0;
    proc_handle_t *handle = file;
    return procfs_poll_dispatch(handle, handle->node, events);
}

int procfs_mount(uint64_t dev, vfs_node_t mnt) {
    if (procfs_root != fake_procfs_root)
        return 0;
    if (procfs_root == mnt)
        return 0;

    spin_lock(&procfs_oplock);

    vfs_merge_nodes_to(mnt, fake_procfs_root);

    mount_node_old_fsid = mnt->fsid;

    procfs_root = mnt;
    mnt->fsid = procfs_id;
    mnt->dev = (PROCFS_DEV_MAJOR << 8) | 0;
    mnt->rdev = (PROCFS_DEV_MAJOR << 8) | 0;

    spin_unlock(&procfs_oplock);

    return 0;
}

void procfs_unmount(vfs_node_t root) {
    if (root == fake_procfs_root)
        return;

    if (root != procfs_root)
        return;

    spin_lock(&procfs_oplock);

    vfs_merge_nodes_to(fake_procfs_root, root);

    root->fsid = mount_node_old_fsid;
    root->dev = root->parent ? root->parent->dev : 0;
    root->rdev = root->parent ? root->parent->rdev : 0;

    procfs_root = fake_procfs_root;

    spin_unlock(&procfs_oplock);
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)procfs_open,
    .close = (vfs_close_t)procfs_close,
    .read = procfs_read,
    .write = (vfs_write_t)procfs_write,
    .readlink = (vfs_readlink_t)procfs_readlink,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)procfs_stat,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)procfs_poll,
    .mount = (vfs_mount_t)procfs_mount,
    .unmount = (vfs_unmount_t)procfs_unmount,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

void procfs_self_open(void *parent, const char *name, vfs_node_t node) {
    procfs_self_handle_t *handle = malloc(sizeof(procfs_self_handle_t));
    handle->self = node;
    node->handle = handle;
    llist_delete(&node->node_for_childs);
    vfs_node_t new_self_node = vfs_node_alloc(node->parent, "self");
    new_self_node->flags |= VFS_NODE_FLAGS_FREE_AFTER_USE;
    new_self_node->type = file_symlink;
    new_self_node->mode = 0644;
    new_self_node->fsid = procfs_self_id;
}

bool procfs_self_close(void *current) {
    procfs_self_handle_t *handle = current;
    handle->deleted = true;
    free(handle);

    return true;
}

ssize_t procfs_self_readlink(vfs_node_t file, void *addr, size_t offset,
                             size_t size) {
    char pid[32];
    ssize_t len = sprintf(pid, "%d", current_task->pid);
    len = MIN(len, (ssize_t)size);
    memcpy(addr, pid, len);
    return len;
}

void procfs_self_free_handle(procfs_self_handle_t *handle) { free(handle); }

static struct vfs_callback procfs_self_callbacks = {
    .open = (vfs_open_t)procfs_self_open,
    .close = (vfs_close_t)procfs_self_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_readlink_t)procfs_self_readlink,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .resize = (vfs_resize_t)dummy,

    .free_handle = (vfs_free_handle_t)procfs_self_free_handle,
};

fs_t procfs = {
    .name = "proc",
    .magic = 0x9fa0,
    .callback = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

fs_t procfs_self = {
    .name = "proc_self",
    .magic = 0,
    .callback = &procfs_self_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

extern struct llist_header mount_points;

int procfs_mount_point_count = 0;

void proc_init() {
    procfs_id = vfs_regist(&procfs);
    procfs_self_id = vfs_regist(&procfs_self);

    fake_procfs_root = vfs_node_alloc(NULL, "fakeproc");
    fake_procfs_root->fsid = procfs_id;

    procfs_root = fake_procfs_root;

    vfs_node_t self_node = vfs_child_append(procfs_root, "self", NULL);
    self_node->flags |= VFS_NODE_FLAGS_FREE_AFTER_USE;
    self_node->type = file_symlink;
    self_node->mode = 0644;
    self_node->fsid = procfs_self_id;

    procfs_nodes_init();

    struct mount_point *tmp1, *tmp2;
    llist_for_each(tmp1, tmp2, &mount_points, node) {
        procfs_mount_point_count++;
    }
}

void procfs_on_new_task(task_t *task) {
    if (task->pid == 0)
        return;

    spin_lock(&procfs_oplock);

    char name[MAX_PID_NAME_LEN];
    sprintf(name, "%d", task->pid);

    vfs_node_t node = vfs_child_append(procfs_root, name, NULL);
    node->type = file_dir;
    node->mode = 0644;

    vfs_node_t cmdline = vfs_child_append(node, "cmdline", NULL);
    cmdline->type = file_none;
    cmdline->mode = 0700;
    proc_handle_t *handle = malloc(sizeof(proc_handle_t));
    cmdline->handle = handle;
    handle->node = cmdline;
    handle->task = task;
    sprintf(handle->name, "proc_cmdline");

    vfs_node_t self_environ = vfs_child_append(node, "environ", NULL);
    self_environ->type = file_none;
    self_environ->mode = 0700;
    proc_handle_t *self_environ_handle = malloc(sizeof(proc_handle_t));
    self_environ->handle = self_environ_handle;
    self_environ_handle->node = self_environ;
    self_environ_handle->task = task;
    sprintf(self_environ_handle->name, "environ");

    vfs_node_t self_maps = vfs_child_append(node, "maps", NULL);
    self_maps->type = file_none;
    self_maps->mode = 0700;
    proc_handle_t *self_maps_handle = malloc(sizeof(proc_handle_t));
    self_maps->handle = self_maps_handle;
    self_maps_handle->node = self_maps;
    self_maps_handle->task = task;
    sprintf(self_maps_handle->name, "proc_maps");

    vfs_node_t self_stat = vfs_child_append(node, "stat", NULL);
    self_stat->type = file_none;
    self_stat->mode = 0700;
    proc_handle_t *self_stat_handle = malloc(sizeof(proc_handle_t));
    self_stat->handle = self_stat_handle;
    self_stat_handle->node = self_stat;
    self_stat_handle->task = task;
    sprintf(self_stat_handle->name, "proc_stat");

    vfs_node_t self_cgroup = vfs_child_append(node, "cgroup", NULL);
    self_cgroup->type = file_none;
    self_cgroup->mode = 0700;
    proc_handle_t *self_cgroup_handle = malloc(sizeof(proc_handle_t));
    self_cgroup->handle = self_cgroup_handle;
    self_cgroup_handle->node = self_cgroup;
    self_cgroup_handle->task = task;
    sprintf(self_cgroup_handle->name, "proc_cgroup");

    vfs_node_t self_mountinfo = vfs_child_append(node, "mountinfo", NULL);
    self_mountinfo->type = file_none;
    self_mountinfo->mode = 0700;
    proc_handle_t *self_mountinfo_handle = malloc(sizeof(proc_handle_t));
    self_mountinfo->handle = self_mountinfo_handle;
    self_mountinfo_handle->node = self_mountinfo;
    self_mountinfo_handle->task = task;
    sprintf(self_mountinfo_handle->name, "proc_mountinfo");

    vfs_node_t self_exe = vfs_child_append(node, "exe", NULL);
    self_exe->type = file_symlink;
    self_exe->mode = 0700;
    proc_handle_t *self_exe_handle = malloc(sizeof(proc_handle_t));
    self_exe->handle = self_exe_handle;
    self_exe_handle->node = self_exe;
    self_exe_handle->task = task;
    sprintf(self_exe_handle->name, "exe");

    vfs_node_t self_fd = vfs_child_append(node, "fd", NULL);
    self_fd->type = file_dir;
    self_fd->mode = 0700;

    node->refcount++;
    task->procfs_node = node;

    spin_unlock(&procfs_oplock);
}

void procfs_on_open_file(task_t *task, int fd) {
    vfs_node_t fd_root = vfs_open_at(task->procfs_node, "fd");
    if (!fd_root)
        return;

    if (!task->fd_info->fds[fd])
        return;

    char fd_name[4];
    sprintf(fd_name, "%d", fd);
    vfs_node_t fd_node = vfs_child_append(fd_root, fd_name, NULL);
    fd_node->type = file_symlink;
    fd_node->mode = 0700;
    proc_handle_t *fd_node_handle = malloc(sizeof(proc_handle_t));
    fd_node->handle = fd_node_handle;
    fd_node_handle->node = fd_node;
    fd_node_handle->task = task;
    vfs_node_t node = task->fd_info->fds[fd]->node;
    if (node->name) {
        char *link_name = vfs_get_fullpath(node);
        strcpy(fd_node_handle->content, link_name);
        free(link_name);
    }
    sprintf(fd_node_handle->name, "fd");
}

void procfs_on_close_file(task_t *task, int fd) {
    char name[3 + 4];
    sprintf(name, "fd/%d", fd);
    vfs_node_t fd_node = vfs_open_at(task->procfs_node, name);
    if (!fd_node)
        return;

    vfs_free(fd_node);
}

void procfs_on_exit_task(task_t *task) {
    if (task->pid == 0)
        return;

    spin_lock(&procfs_oplock);

    char name[MAX_PID_NAME_LEN];
    sprintf(name, "%d", task->pid);

    vfs_close(task->procfs_node);
    task->procfs_node = NULL;

    vfs_node_t node = vfs_open_at(procfs_root, name);
    if (!node)
        goto done;

    vfs_free(node);

done:
    spin_unlock(&procfs_oplock);
}
