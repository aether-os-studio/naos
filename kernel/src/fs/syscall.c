#include <arch/arch.h>
#include <task/task.h>
#include <fs/syscall.h>

uint64_t sys_open(const char *name, uint64_t mode, uint64_t flags)
{
    uint64_t i;
    for (i = 0; i < MAX_FD_NUM; i++)
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
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    current_task->fds[fd] = NULL;

    return 0;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len)
{
    if (fd == 0)
    {
        uint8_t scancode = get_keyboard_input();
        *(uint8_t *)buf = scancode;

        return 1;
    }

    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    return vfs_read(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len)
{
    if (fd == 1 || fd == 2)
    {
        printk("%s", buf);
        return len;
    }

    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    return vfs_write(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    switch (whence)
    {
    case SEEK_SET:
        current_task->fds[fd]->offset = offset;
        break;
    case SEEK_CUR:
        current_task->fds[fd]->offset += offset;
        if (current_task->fds[fd]->offset > current_task->fds[fd]->size)
        {
            current_task->fds[fd]->offset = current_task->fds[fd]->size;
        }
        break;
    case SEEK_END:
        current_task->fds[fd]->offset = current_task->fds[fd]->size - offset;
        break;

    default:
        return (uint64_t)-ENOSYS;
        break;
    }

    return current_task->fds[fd]->offset;
}

uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg)
{
    if (fd >= MAX_FD_NUM)
    {
        return (uint64_t)-EBADFD;
    }

    return 0;
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
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (!current_task->fds[fd])
        return (uint64_t)-EBADF;
    if (current_task->fds[fd]->type != file_dir)
        return (uint64_t)-ENOTDIR;

    dirent_t *dents = (dirent_t *)buf;
    vfs_node_t node = current_task->fds[fd];
    uint64_t len = 0;
    list_foreach(node->child, i)
    {
        vfs_node_t node = (vfs_node_t)i->data;
        strncpy(dents[len].name, node->name, 255);
        dents[len].type = node->type;
        len++;
    }

    return len;
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

uint64_t sys_getcwd(char *cwd)
{
    char *str = vfs_get_fullpath(current_task->cwd);
    strcpy(cwd, str);
    free(str);
    return 0;
}
