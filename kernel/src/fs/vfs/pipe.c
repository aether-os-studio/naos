#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>

vfs_node_t pipefs_root;
int pipefs_id = 0;
static int pipefd_id = 0;

static void dummy() {}

void pipefs_open(void *parent, const char *name, vfs_node_t node)
{
    (void)parent;
    (void)name;
}

static void wake_blocked_tasks(task_block_list_t *head)
{
    task_block_list_t *current = head->next;
    head->next = NULL;

    while (current)
    {
        task_block_list_t *next = current->next;
        if (current->task)
        {
            task_unblock(current->task, EOK);
        }
        free(current);
        current = next;
    }
}

ssize_t pipefs_read(void *file, void *addr, size_t offset, size_t size)
{
    if (size > PIPE_BUFF)
        size = PIPE_BUFF;

    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    arch_disable_interrupt();
    while (pipe->lock)
    {
        arch_enable_interrupt();
        arch_pause();
        arch_disable_interrupt();
    }
    pipe->lock = true;
    arch_enable_interrupt();

    while (pipe->assigned == 0 && pipe->writeFds > 0)
    {
        arch_disable_interrupt();
        task_block_list_t *new_block = malloc(sizeof(task_block_list_t));
        new_block->task = current_task;
        new_block->next = NULL;

        task_block_list_t *browse = &pipe->blocking_read;
        while (browse->next)
            browse = browse->next;
        browse->next = new_block;

        task_block(current_task, TASK_BLOCKING, -1);

        while (current_task->state == TASK_BLOCKING)
        {
            arch_enable_interrupt();
            arch_pause();
        }
        arch_disable_interrupt();
    }

    if (pipe->assigned == 0)
    {
        pipe->lock = false;
        return 0;
    }

    int to_copy = pipe->assigned;
    if (to_copy > size)
        to_copy = size;

    memcpy(addr, pipe->buf, to_copy);
    pipe->assigned -= to_copy;
    memmove(pipe->buf, &pipe->buf[to_copy], PIPE_BUFF - to_copy);
    pipe->lock = false;

    wake_blocked_tasks(&pipe->blocking_write);

    return to_copy;
}

ssize_t pipe_write_inner(void *file, const void *addr, size_t size)
{
    if (size > PIPE_BUFF)
        size = PIPE_BUFF;

    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    arch_disable_interrupt();
    while (pipe->lock)
    {
        arch_enable_interrupt();
        arch_pause();
        arch_disable_interrupt();
    }
    pipe->lock = true;
    arch_enable_interrupt();

    while ((pipe->assigned + size) > PIPE_BUFF && pipe->readFds > 0)
    {
        task_block_list_t *new_block = malloc(sizeof(task_block_list_t));
        new_block->task = current_task;
        new_block->next = NULL;

        task_block_list_t *browse = &pipe->blocking_write;

        while (browse->next)
            browse = browse->next;
        browse->next = new_block;

        task_block(current_task, TASK_BLOCKING, -1);

        while (current_task->state == TASK_BLOCKING)
        {
            arch_enable_interrupt();
            arch_pause();
        }
        arch_disable_interrupt();
    }

    memcpy(&pipe->buf[pipe->assigned], addr, size);
    pipe->assigned += size;

    wake_blocked_tasks(&pipe->blocking_read);

    pipe->lock = false;

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
    case FIOCLEX:
        return 0;
    case TIOCGWINSZ:
    case TIOCSWINSZ:
        return -ENOTTY;
    default:
        return -ENOSYS;
    }
}

void pipefs_close(void *current)
{
    pipe_specific_t *spec = (pipe_specific_t *)current;
    pipe_info_t *pipe = spec->info;

    if (spec->write)
    {
        if (pipe->writeFds > 0)
            pipe->writeFds--;
    }
    else
    {
        if (pipe->readFds > 0)
            pipe->readFds--;
    }

    if (pipe->writeFds == 0)
    {
        wake_blocked_tasks(&pipe->blocking_read);
    }
    if (pipe->readFds == 0)
    {
        wake_blocked_tasks(&pipe->blocking_write);
    }

    if (!pipe->readFds && !pipe->writeFds)
    {
        pipe->lock = true;
        free(pipe);
    }
}

int pipefs_poll(void *file, size_t events)
{
    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    int out = 0;

    pipe->lock = true;
    if (events & EPOLLIN)
    {
        if (!pipe->writeFds)
            out |= EPOLLHUP;
        else if (pipe->assigned > 0)
            out |= EPOLLIN;
    }

    if (events & EPOLLOUT)
    {
        if (!pipe->readFds)
            out |= EPOLLERR;
        else if (pipe->assigned < PIPE_BUFF)
            out |= POLLOUT;
    }
    pipe->lock = false;
    return out;
}

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)pipefs_open,
    .close = (vfs_close_t)pipefs_close,
    .read = pipefs_read,
    .write = pipefs_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)pipefs_ioctl,
    .poll = pipefs_poll,
};

void pipefs_init()
{
    pipefs_id = vfs_regist("pipefs", &callbacks);
    pipefs_root = vfs_node_alloc(rootdir, "pipe");
    pipefs_root->type = file_dir;
}

// 创建一个新管道
int sys_pipe(int pipefd[2])
{
    int i1 = -1;
    for (i1 = 3; i1 < MAX_FD_NUM; i1++)
    {
        if (current_task->fds[i1] == NULL)
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

    sprintf(buf, "pipe%d", pipefd_id++);
    vfs_node_t node_output = vfs_node_alloc(pipefs_root, buf);
    node_output->type = file_pipe;
    node_output->fsid = pipefs_id;

    pipe_info_t *info = (pipe_info_t *)malloc(sizeof(pipe_info_t));
    memset(info, 0, sizeof(pipe_info_t));
    info->readFds = 1;
    info->writeFds = 1;
    info->blocking_read.next = NULL;
    info->blocking_write.next = NULL;
    info->lock = false;

    pipe_specific_t *read_spec = (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    read_spec->write = false;
    read_spec->info = info;

    pipe_specific_t *write_spec = (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    write_spec->write = true;
    write_spec->info = info;

    node_input->handle = read_spec;
    node_output->handle = write_spec;

    current_task->fds[i1] = node_input;

    int i2 = -1;
    for (i2 = 3; i2 < MAX_FD_NUM; i2++)
    {
        if (current_task->fds[i2] == NULL)
        {
            break;
        }
    }

    if (i2 == MAX_FD_NUM)
    {
        return -EBADF;
    }

    current_task->fds[i2] = node_output;

    pipefd[0] = i1;
    pipefd[1] = i2;

    return 0;
}
