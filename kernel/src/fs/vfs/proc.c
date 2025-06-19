#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <task/task.h>

__attribute__((used, section(".limine_requests"))) static volatile struct limine_executable_cmdline_request executable_cmdline_request = {
    .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
};

vfs_node_t cmdline = NULL;

ssize_t procfs_read(void *file, void *addr, size_t offset, size_t size)
{
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
        int len = strlen(task->name);
        if (len > size)
            return -ERANGE;
        memcpy(addr, task->name, len + 1);
        return len + 1;
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

static struct vfs_callback callbacks =
    {
        .open = (vfs_open_t)procfs_open,
        .close = (vfs_close_t)dummy,
        .read = procfs_read,
        .write = (vfs_write_t)dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .delete = (vfs_del_t)dummy,
        .rename = (vfs_rename_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
        .map = (vfs_mapfile_t)dummy,
        .poll = (vfs_poll_t)dummy,
        .mount = (vfs_mount_t)dummy,
        .unmount = (vfs_unmount_t)dummy,
};

void proc_init()
{
    procfs_id = vfs_regist("proc", &callbacks);
    procfs_root = vfs_node_alloc(rootdir, "proc");
    procfs_root->type = file_dir;
    procfs_root->mode = 0644;
    procfs_root->fsid = procfs_id;

    vfs_node_t procfs_self = vfs_node_alloc(procfs_root, "self");
    procfs_self->type = file_dir;
    procfs_self->mode = 0644;

    vfs_node_t self_exe = vfs_node_alloc(procfs_self, "exe");
    self_exe->type = file_none;
    self_exe->mode = 0700;
    proc_handle_t *handle = malloc(sizeof(proc_handle_t));
    self_exe->handle = handle;
    handle->task = NULL;
    sprintf(handle->name, "self/exe");

    cmdline = vfs_node_alloc(procfs_root, "cmdline");
    cmdline->type = file_none;
    cmdline->mode = 0700;
    handle = malloc(sizeof(proc_handle_t));
    cmdline->handle = handle;
    handle->task = NULL;
    sprintf(handle->name, "cmdline");
}
