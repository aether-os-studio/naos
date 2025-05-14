#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>

// 全局管道数组
static pipe_t pipes[MAX_PIPES];
static int pipes_initialized = 0;

vfs_node_t pipefs_root;
int pipefs_id;
static int pipefd_id = 0;

static void dummy() {}

void pipefs_open(void *parent, const char *name, vfs_node_t node)
{
    (void)parent;
    (void)name;
    node->fsid = pipefs_id;
}

ssize_t pipefs_read(void *file, void *addr, size_t offset, size_t size)
{
    pipe_t *pipe = file;

    size_t bytes_read = 0;

    // 简单实现 - 实际需要同步机制
    while (bytes_read < size && pipe->read_pos != pipe->write_pos)
    {
        ((uint8_t *)addr)[bytes_read++] = pipe->buffer[pipe->read_pos];
        pipe->read_pos = (pipe->read_pos + 1) % PIPE_BUF_SIZE;
    }

    return bytes_read;
}

ssize_t pipefs_write(void *file, const void *addr, size_t offset, size_t size)
{
    pipe_t *pipe = file;

    size_t bytes_written = 0;

    // 简单实现 - 实际需要同步机制
    while (bytes_written < size &&
           ((pipe->write_pos + 1) % PIPE_BUF_SIZE) != pipe->read_pos)
    {
        pipe->buffer[pipe->write_pos] = ((uint8_t *)addr)[bytes_written++];
        pipe->write_pos = (pipe->write_pos + 1) % PIPE_BUF_SIZE;
    }

    return bytes_written;
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
    pipe_t *pipe = current;
    pipe->reference_count--;
    if (pipe->reference_count == 0)
        memset(pipe, 0, sizeof(pipe_t));
}

void pipefs_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
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

// 初始化管道系统
void init_pipes()
{
    if (pipes_initialized)
        return;

    memset(pipes, 0, sizeof(pipes));
    for (int i = 0; i < MAX_PIPES; i++)
    {
        pipes[i].reference_count = 0;
    }

    pipes_initialized = 1;
}

// 创建一个新管道
int sys_pipe(int pipefd[2])
{
    if (!pipes_initialized)
    {
        init_pipes();
    }

    int i = -1;
    for (i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return -EBADF;
    }

    // 查找空闲的管道
    int pipe_idx = -1;
    for (int j = 0; j < MAX_PIPES; j++)
    {
        if (!pipes[j].reference_count)
        {
            pipe_idx = j;
            break;
        }
    }

    if (pipe_idx == -1)
    {
        return -1; // 没有可用的管道
    }

    char buf[16];
    sprintf(buf, "pipe%d", pipefd_id++);

    vfs_node_t node_input = vfs_node_alloc(pipefs_root, buf);
    node_input->type = file_pipe;
    node_input->handle = &pipes[pipe_idx];
    pipes[pipe_idx].reference_count++;
    node_input->fsid = pipefs_id;

    vfs_node_t node_output = vfs_node_alloc(pipefs_root, buf);
    node_output->type = file_pipe;
    node_output->handle = &pipes[pipe_idx];
    pipes[pipe_idx].reference_count++;
    node_output->fsid = pipefs_id;

    current_task->fds[i] = node_input;
    current_task->fds[i + 1] = node_output;

    pipefd[0] = i;
    pipefd[1] = i + 1;

    return 0;
}
