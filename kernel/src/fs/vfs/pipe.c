#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>

vfs_node_t pipefs_root;
int pipefs_id = 0;
static int pipefd_id = 0;

static int dummy()
{
    return 0;
}

void pipefs_open(void *parent, const char *name, vfs_node_t node)
{
    (void)parent;
    (void)name;
}

ssize_t pipefs_read(void *file, void *addr, size_t offset, size_t size)
{
    if (size > PIPE_BUFF)
        size = PIPE_BUFF;

    pipe_specific_t *spec = (pipe_specific_t *)file;
    if (!spec)
        return -EINVAL;
    pipe_info_t *pipe = spec->info;
    if (!pipe)
        return -EINVAL;

    spin_lock(&pipe->lock);

    uint32_t available = (pipe->write_ptr - pipe->read_ptr) % PIPE_BUFF;
    if (available == 0)
    {
        fd_t *fd = container_of(spec->node, fd_t, node);
        if (fd->flags & O_NONBLOCK)
        {
            spin_unlock(&pipe->lock);
            return -EWOULDBLOCK;
        }

        if (pipe->write_fds == 0)
        {
            spin_unlock(&pipe->lock);
            return 0;
        }
        arch_disable_interrupt();
        task_block_list_t *new_block = malloc(sizeof(task_block_list_t));
        new_block->task = current_task;
        new_block->next = NULL;

        task_block_list_t *browse = &pipe->blocking_read;
        while (browse->next)
            browse = browse->next;
        browse->next = new_block;

        spin_unlock(&pipe->lock);

        task_block(current_task, TASK_BLOCKING, -1);
    }
    spin_unlock(&pipe->lock);

    available = (pipe->write_ptr - pipe->read_ptr) % PIPE_BUFF;

    // 实际读取量
    uint32_t to_read = MIN(size, available);

    if (available == 0)
    {
        spin_unlock(&pipe->lock);
        return 0;
    }

    // 分两种情况拷贝数据
    if (pipe->read_ptr + to_read <= PIPE_BUFF)
    {
        memcpy(addr, &pipe->buf[pipe->read_ptr], to_read);
    }
    else
    {
        uint32_t first_chunk = PIPE_BUFF - pipe->read_ptr;
        memcpy(addr, &pipe->buf[pipe->read_ptr], first_chunk);
        memcpy(addr + first_chunk, pipe->buf, to_read - first_chunk);
    }

    // 更新读指针
    pipe->read_ptr = (pipe->read_ptr + to_read) % PIPE_BUFF;

    wake_blocked_tasks(&pipe->blocking_write);

    spin_unlock(&pipe->lock);

    return to_read;
}

ssize_t pipe_write_inner(void *file, const void *addr, size_t size)
{
    if (size > PIPE_BUFF)
        size = PIPE_BUFF;

    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    spin_lock(&pipe->lock);

    uint32_t free_space = PIPE_BUFF - ((pipe->write_ptr - pipe->read_ptr) % PIPE_BUFF);
    if (free_space < size)
    {
        if (pipe->read_fds == 0)
        {
            spin_unlock(&pipe->lock);
            return -EPIPE;
        }
        task_block_list_t *new_block = malloc(sizeof(task_block_list_t));
        new_block->task = current_task;
        new_block->next = NULL;

        task_block_list_t *browse = &pipe->blocking_write;

        while (browse->next)
            browse = browse->next;
        browse->next = new_block;

        spin_unlock(&pipe->lock);

        task_block(current_task, TASK_BLOCKING, -1);

        while (current_task->state == TASK_BLOCKING)
        {
            arch_enable_interrupt();
            arch_pause();
        }
        arch_disable_interrupt();
    }

    if (pipe->write_ptr + size <= PIPE_BUFF)
    {
        memcpy(&pipe->buf[pipe->write_ptr], addr, size);
    }
    else
    {
        uint32_t first_chunk = PIPE_BUFF - pipe->write_ptr;
        memcpy(&pipe->buf[pipe->write_ptr], addr, first_chunk);
        memcpy(pipe->buf, addr + first_chunk, size - first_chunk);
    }

    pipe->write_ptr = (pipe->write_ptr + size) % PIPE_BUFF;

    wake_blocked_tasks(&pipe->blocking_read);

    spin_unlock(&pipe->lock);

    return size;
}

ssize_t pipefs_write(void *file, const void *addr, size_t offset, size_t size)
{
    int ret = 0;
    size_t chunks = size / PIPE_BUFF;
    size_t remainder = size % PIPE_BUFF;
    if (chunks)
        for (size_t i = 0; i < chunks; i++)
        {
            int cycle = 0;
            while (cycle != PIPE_BUFF)
                cycle +=
                    pipe_write_inner(file, addr + i * PIPE_BUFF + cycle, PIPE_BUFF - cycle);
            ret += cycle;
        }

    if (remainder)
    {
        size_t cycle = 0;
        while (cycle != remainder)
            cycle += pipe_write_inner(file, addr + chunks * PIPE_BUFF + cycle,
                                      remainder - cycle);
        ret += cycle;
    }

    return ret;
}

int pipefs_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    switch (cmd)
    {
    default:
        return -ENOSYS;
    }
}

bool pipefs_close(void *current)
{
    pipe_specific_t *spec = (pipe_specific_t *)current;
    pipe_info_t *pipe = spec->info;

    spin_lock(&pipe->lock);
    if (spec->write)
    {
        pipe->write_fds--;
    }
    else
    {
        pipe->read_fds--;
    }

    if (!pipe->write_fds)
        wake_blocked_tasks(&pipe->blocking_read);
    if (!pipe->read_fds)
        wake_blocked_tasks(&pipe->blocking_write);

    if (pipe->write_fds == 0 && pipe->read_fds == 0)
    {
        free(pipe);
    }
    spin_unlock(&pipe->lock);

    free(spec);

    list_delete(pipefs_root->child, spec->node);

    return true;
}

int pipefs_poll(void *file, size_t events)
{
    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    int out = 0;

    spin_lock(&pipe->lock);
    if (events & EPOLLIN)
    {
        if (!pipe->write_fds)
            out |= EPOLLHUP;
        else if (pipe->write_ptr != pipe->read_ptr)
            out |= EPOLLIN;
    }

    if (events & EPOLLOUT)
    {
        if (!pipe->read_fds)
            out |= EPOLLERR;
        else if (pipe->assigned < PIPE_BUFF)
            out |= EPOLLOUT;
    }
    spin_unlock(&pipe->lock);
    return out;
}

vfs_node_t pipe_dup(vfs_node_t node)
{
    pipe_specific_t *spec = node->handle;
    pipe_info_t *pipe = spec->info;
    if (spec->write)
    {
        pipe->write_fds++;
    }
    else
    {
        pipe->read_fds++;
    }

    return node;
}

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)pipefs_open,
    .close = (vfs_close_t)pipefs_close,
    .read = pipefs_read,
    .write = pipefs_write,
    .readlink = (vfs_read_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)pipefs_ioctl,
    .poll = pipefs_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)pipe_dup,
};

void pipefs_init()
{
    pipefs_id = vfs_regist("pipefs", &callbacks);
    pipefs_root = vfs_node_alloc(rootdir, "pipe");
    pipefs_root->type = file_dir;
    pipefs_root->mode = 0644;
    pipefs_root->fsid = pipefs_id;
}

int sys_pipe(int pipefd[2], uint64_t flags)
{
    int i1 = -1;
    for (i1 = 3; i1 < MAX_FD_NUM; i1++)
    {
        if (current_task->fd_info->fds[i1] == NULL)
        {
            break;
        }
    }

    if (i1 == MAX_FD_NUM)
    {
        return -EBADF;
    }

    char buf[16];
    sprintf(buf, "pipe%d", pipefd_id++);

    vfs_node_t node_input = vfs_node_alloc(pipefs_root, buf);
    node_input->type = file_pipe;
    node_input->fsid = pipefs_id;
    node_input->refcount++;
    pipefs_root->mode = 0700;

    sprintf(buf, "pipe%d", pipefd_id++);
    vfs_node_t node_output = vfs_node_alloc(pipefs_root, buf);
    node_output->type = file_pipe;
    node_output->fsid = pipefs_id;
    node_output->refcount++;
    pipefs_root->mode = 0700;

    pipe_info_t *info = (pipe_info_t *)malloc(sizeof(pipe_info_t));
    memset(info, 0, sizeof(pipe_info_t));
    info->read_fds = 1;
    info->write_fds = 1;
    info->blocking_read.next = NULL;
    info->blocking_write.next = NULL;
    info->lock.lock = 0;
    info->read_ptr = 0;
    info->write_ptr = 0;
    info->assigned = 0;

    pipe_specific_t *read_spec = (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    read_spec->write = false;
    read_spec->info = info;
    read_spec->node = node_input;

    pipe_specific_t *write_spec = (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    write_spec->write = true;
    write_spec->info = info;
    write_spec->node = node_output;

    node_input->handle = read_spec;
    node_output->handle = write_spec;

    current_task->fd_info->fds[i1] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i1]->node = node_input;
    current_task->fd_info->fds[i1]->offset = 0;
    current_task->fd_info->fds[i1]->flags = flags;

    int i2 = -1;
    for (i2 = 3; i2 < MAX_FD_NUM; i2++)
    {
        if (current_task->fd_info->fds[i2] == NULL)
        {
            break;
        }
    }

    if (i2 == MAX_FD_NUM)
    {
        return -EBADF;
    }

    current_task->fd_info->fds[i2] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i2]->node = node_output;
    current_task->fd_info->fds[i2]->offset = 0;
    current_task->fd_info->fds[i2]->flags = flags;

    pipefd[0] = i1;
    pipefd[1] = i2;

    return 0;
}
