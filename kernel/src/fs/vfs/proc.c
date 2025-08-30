#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <task/task.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_executable_cmdline_request executable_cmdline_request = {
    .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
};

spinlock_t procfs_oplock = {0};

vfs_node_t cmdline = NULL;

const char filesystems_content[] = "nodev\tsysfs\n"
                                   "nodev\ttmpfs\n"
                                   "nodev\tproc\n"
                                   "     \text4\n"
                                   "     \text3\n"
                                   "     \text2\n";

ssize_t procfs_read(fd_t *fd, void *addr, size_t offset, size_t size)
{
    void *file = fd->node->handle;
    proc_handle_t *handle = (proc_handle_t *)file;
    if (!handle)
    {
        return -EINVAL;
    }
    task_t *task;
    if (handle->task == NULL)
    {
        task = current_task;
    }
    else
    {
        task = handle->task;
    }

    if (!strcmp(handle->name, "self/exe"))
    {
        if (task->exec_node)
        {
            char *fullpath = vfs_get_fullpath(task->exec_node);
            strncpy(addr, fullpath, size);
            free(fullpath);
            return strlen(addr);
        }
        else
            return 0;
    }
    else if (!strcmp(handle->name, "filesystems"))
    {
        if (offset < strlen(filesystems_content))
        {
            memcpy(addr, filesystems_content + offset, size);
            return size;
        }
        else
            return 0;
    }
    else if (!strcmp(handle->name, "cmdline"))
    {
        ssize_t len = strlen(executable_cmdline_request.response->cmdline);
        if (len == 0)
            return 0;
        len = (len + 1) > size ? size : len + 1;
        memcpy(addr, executable_cmdline_request.response->cmdline, len);
        return len;
    }
    else if (!strcmp(handle->name, "proc_cmdline"))
    {
        ssize_t len = strlen(task->cmdline);
        if (len == 0)
            return 0;
        len = (len + 1) > size ? size : len + 1;
        memcpy(addr, task->cmdline, len);
        return len;
    }
    else if (!strcmp(handle->name, "dri_name"))
    {
        char name[] = "naos_drm";
        int len = strlen(name);
        memcpy(addr, name, len);
        return len;
    }

    return 0;
}

vfs_node_t procfs_root = NULL;
int procfs_id = 0;

static int dummy()
{
    return 0;
}

void procfs_open(void *parent, const char *name, vfs_node_t node)
{
}

bool procfs_close(void *current)
{
    return false;
}

ssize_t procfs_readlink(vfs_node_t node, void *addr, size_t offset, size_t size)
{
    proc_handle_t *handle = node->handle;
    if (!strcmp(handle->name, "self/exe") && current_task->exec_node)
    {
        char *fullpath = vfs_get_fullpath(current_task->exec_node);
        int len = strlen(fullpath);
        len = MIN(len, size);
        memcpy(addr, fullpath, len);
        return len;
    }

    return 0;
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)procfs_open,
    .close = (vfs_close_t)dummy,
    .read = procfs_read,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_readlink_t)procfs_readlink,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

void proc_init()
{
    procfs_id = vfs_regist("proc", &callbacks);
    procfs_root = vfs_child_append(rootdir, "proc", NULL);
    procfs_root->type = file_dir;
    procfs_root->mode = 0644;
    procfs_root->fsid = procfs_id;

    vfs_node_t procfs_self = vfs_node_alloc(procfs_root, "self");
    procfs_self->type = file_dir;
    procfs_self->mode = 0644;

    // vfs_node_t self_exe = vfs_node_alloc(procfs_self, "exe");
    // self_exe->type = file_none;
    // self_exe->mode = 0700;
    // proc_handle_t *self_exe_handle = malloc(sizeof(proc_handle_t));
    // self_exe->handle = self_exe_handle;
    // self_exe_handle->task = NULL;
    // self_exe->linkto = rootdir;
    // sprintf(self_exe_handle->name, "self/exe");

    vfs_node_t self_environ = vfs_node_alloc(procfs_self, "environ");
    self_environ->type = file_none;
    self_environ->mode = 0700;
    proc_handle_t *self_environ_handle = malloc(sizeof(proc_handle_t));
    self_environ->handle = self_environ_handle;
    self_environ_handle->task = NULL;
    sprintf(self_environ_handle->name, "self/environ");

    cmdline = vfs_node_alloc(procfs_root, "cmdline");
    cmdline->type = file_none;
    cmdline->mode = 0700;
    proc_handle_t *handle = malloc(sizeof(proc_handle_t));
    cmdline->handle = handle;
    handle->task = NULL;
    sprintf(handle->name, "cmdline");

    vfs_node_t filesystems = vfs_node_alloc(procfs_root, "filesystems");
    filesystems->type = file_none;
    filesystems->mode = 0700;
    proc_handle_t *filesystems_handle = malloc(sizeof(proc_handle_t));
    filesystems->handle = filesystems_handle;
    filesystems_handle->task = NULL;
    sprintf(filesystems_handle->name, "filesystems");
}

void procfs_on_new_task(task_t *task)
{
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
    handle->task = task;
    sprintf(handle->name, "proc_cmdline");

    spin_unlock(&procfs_oplock);
}

void procfs_on_exit_task(task_t *task)
{
    spin_lock(&procfs_oplock);

    char name[6 + MAX_PID_NAME_LEN];
    sprintf(name, "/proc/%d", task->pid);

    vfs_node_t node = vfs_open(name);
    if (node)
    {
        list_delete(node->parent->child, node);
        vfs_free(node);
    }

    spin_unlock(&procfs_oplock);
}
