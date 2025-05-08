#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <net/socket.h>

uint64_t sys_open(const char *name, uint64_t mode, uint64_t flags)
{
    (void)mode;
    (void)flags;

    uint64_t i;
    for (i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return (uint64_t)-EBADFD;
    }

    vfs_node_t node = vfs_open(name);
    if (!node)
    {
        return (uint64_t)-ENOENT;
    }

    current_task->fds[i] = node;

    return i;
}

uint64_t sys_close(uint64_t fd)
{
    if (fd > MAX_FD_NUM && fd <= MAX_SOCKETS)
    {
        sys_socket_close(fd);
    }

    if (fd >= MAX_SOCKETS || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    current_task->fds[fd]->offset = 0;
    if (current_task->fds[fd]->type == file_pipe && current_task->fds[fd]->handle)
    {
        pipe_t *pipe = current_task->fds[fd]->handle;
        pipe->reference_count--;
    }
    vfs_close(current_task->fds[fd]);
    current_task->fds[fd] = NULL;

    return 0;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len)
{
    if (fd > MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    ssize_t ret = vfs_read(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
    sys_lseek(fd, len, SEEK_CUR);
    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len)
{
    if (fd > MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    ssize_t ret = vfs_write(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
    sys_lseek(fd, len, SEEK_CUR);
    return ret;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence)
{
    if (fd > MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    int64_t real_offset = offset;
    if (real_offset < 0 && current_task->fds[fd]->type == file_none && whence != SEEK_CUR)
        return (uint64_t)-EBADF;

    switch (whence)
    {
    case SEEK_SET:
        current_task->fds[fd]->offset = real_offset;
        break;
    case SEEK_CUR:
        current_task->fds[fd]->offset += real_offset;
        if ((int64_t)current_task->fds[fd]->offset < 0)
        {
            current_task->fds[fd]->offset = 0;
        }
        else if (current_task->fds[fd]->offset > current_task->fds[fd]->size)
        {
            current_task->fds[fd]->offset = current_task->fds[fd]->size;
        }

        break;
    case SEEK_END:
        current_task->fds[fd]->offset = current_task->fds[fd]->size - real_offset;
        break;

    default:
        return (uint64_t)-ENOSYS;
        break;
    }

    return current_task->fds[fd]->offset;
}

uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg)
{
    if (fd > MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    return vfs_ioctl(current_task->fds[fd], cmd, arg);
}

uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count)
{
    if ((uint64_t)iovec == 0)
    {
        return -EINVAL;
    }

    uint64_t len = 0;

    for (uint64_t i = 0; i < count; i++)
    {
        size_t iov_len = iovec[i].len;
        len += iov_len;
    }

    uint8_t *buf = (uint8_t *)malloc(len + 1);
    if (!buf)
    {
        return -ENOMEM;
    }
    memset(buf, 0, len + 1);

    int ret = sys_read(fd, buf, len);

    uint8_t *ptr = buf;

    for (uint64_t i = 0; i < count; i++)
    {
        uint8_t *iov_base = iovec[i].iov_base;
        size_t iov_len = iovec[i].len;
        if (iov_len == 0)
        {
            continue;
        }
        memcpy(iov_base, ptr, iov_len);
        ptr += iov_len;
    }

    free(buf);
    return ret;
}

uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count)
{
    if ((uint64_t)iovec == 0)
    {
        return -EINVAL;
    }

    uint64_t len = 0;

    for (uint64_t i = 0; i < count; i++)
    {
        size_t iov_len = iovec[i].len;
        len += iov_len;
    }

    uint8_t *buf = (uint8_t *)malloc(len + 1);
    if (!buf)
    {
        return -ENOMEM;
    }
    memset(buf, 0, len + 1);
    uint8_t *ptr = buf;

    for (uint64_t i = 0; i < count; i++)
    {
        uint8_t *iov_base = iovec[i].iov_base;
        size_t iov_len = iovec[i].len;
        if (iov_len == 0)
        {
            continue;
        }
        memcpy(ptr, iov_base, iov_len);
        ptr += iov_len;
    }

    int ret = sys_write(fd, buf, len);
    free(buf);

    return ret;
}

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size)
{
    if (fd > MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (!current_task->fds[fd])
        return (uint64_t)-EBADF;
    if (current_task->fds[fd]->type != file_dir)
        return (uint64_t)-ENOTDIR;

    struct dirent *dents = (struct dirent *)buf;
    vfs_node_t node = current_task->fds[fd];

    if (node->offset >= list_length(node->child))
    {
        return 0;
    }

    list_foreach(node->child, i)
    {
        vfs_node_t child_node = (vfs_node_t)i->data;
        dents[node->offset].d_ino = 0;
        dents[node->offset].d_off = node->offset * sizeof(struct dirent);
        dents[node->offset].d_reclen = sizeof(struct dirent);
        dents[node->offset].d_type = (child_node->type == file_dir) ? DT_DIR : DT_REG;
        strncpy(dents[node->offset].d_name, child_node->name, 1024);
        node->offset++;
    }

    return node->offset * sizeof(struct dirent);
}

uint64_t sys_chdir(const char *dirname)
{
    vfs_node_t new_cwd = vfs_open(dirname);
    if (!new_cwd)
        return (uint64_t)-ENOENT;
    if (new_cwd->type != file_dir)
        return (uint64_t)-ENOTDIR;

    current_task->cwd = new_cwd;

    return 0;
}

uint64_t sys_getcwd(char *cwd, uint64_t size)
{
    char *str = vfs_get_fullpath(current_task->cwd);
    if (size < strlen(str))
    {
        return (uint64_t)-ERANGE;
    }
    strncpy(cwd, str, size);
    free(str);
    return strlen(str);
}

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg)
{
    switch (command)
    {
    case 1:
        return 0;
        break;
    case 2:
        return 0;
        break;

    default:
        break;
    }

    return (uint64_t)-ENOSYS;
}

uint64_t sys_fstat(uint64_t fd, struct stat *buf)
{
    static uint64_t i = 0;

    if (fd > MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    buf->st_dev = 0;
    buf->st_ino = i++;
    buf->st_nlink = 1;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_rdev = 0;
    buf->st_blksize = DEFAULT_PAGE_SIZE;
    buf->st_size = current_task->fds[fd]->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    return 0;
}

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim)
{
    switch (resource)
    {
    case 7: // max open fds
        lim->rlim_cur = 1024;
        lim->rlim_max = 1024;
        return 0;
    default:
        return (uint64_t)-ENOSYS;
    }
}
