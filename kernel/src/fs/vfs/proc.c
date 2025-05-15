#include <fs/vfs/proc.h>

static vfs_node_t procfs_root = NULL;
static int procfs_id = 0;

static int dummy()
{
    return -ENOSYS;
}

ssize_t procfs_read(void *file, void *addr, size_t offset, size_t size)
{
    procfs_handle_t *handle = file;

    task_t *task = current_task;

    if (handle->task != NULL)
    {
        task = handle->task;
    }

    if (!strcmp(handle->fn, "cmdline"))
    {
        if (handle->node->offset >= strlen(task->cmdline))
            return 0;
        size_t toCopy = strlen(task->cmdline) - handle->node->offset;
        if (toCopy > size)
            toCopy = size;

        memcpy(addr, task->cmdline + handle->node->offset, toCopy);

        return toCopy;
    }

    return 0;
}

static struct vfs_callback callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = procfs_read,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)dummy,
};

void proc_init()
{
    procfs_id = vfs_regist("procfs", &callback);
    procfs_root = vfs_node_alloc(rootdir, "proc");
    procfs_root->type = file_dir;
    procfs_root->fsid = procfs_id;

    vfs_node_t proc_task = procfs_regist_proc(NULL);
}

vfs_node_t procfs_regist_proc(task_t *task)
{
    char buf[16];
    if (task)
        sprintf(buf, "%d", task->pid);
    else
        strcpy(buf, "self");
    vfs_node_t proc_task = vfs_child_append(procfs_root, buf, NULL);
    proc_task->type = file_dir;
    proc_task->handle = malloc(sizeof(procfs_handle_t));
    procfs_handle_t *proc_handle = proc_task->handle;
    proc_handle->node = proc_task;
    proc_handle->task = task;

    vfs_node_t proc_cmdline = vfs_child_append(proc_task, "cmdline", NULL);
    proc_cmdline->type = file_none;
    proc_cmdline->handle = malloc(sizeof(procfs_handle_t));
    procfs_handle_t *cmdline_handle = proc_cmdline->handle;
    cmdline_handle->node = proc_cmdline;
    cmdline_handle->task = task;
    strcpy(cmdline_handle->fn, "cmdline");

    return proc_task;
}

void procfs_unregist_proc(task_t *task)
{
    char buf[256];
    sprintf(buf, "/proc/%d", task->pid);
    vfs_node_t proc_node = vfs_open(buf);

    list_delete(procfs_root->child, proc_node);

    vfs_close(proc_node);
}
