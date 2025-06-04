#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <net/net_syscall.h>

static int eventfd_id = 0;

char *at_resolve_pathname(int dirfd, char *pathname)
{
    if (pathname[0] == '/')
    { // by absolute pathname
        return strdup(pathname);
    }
    else if (pathname[0] != '/')
    {
        if (dirfd == AT_FDCWD)
        { // relative to cwd
            return strdup(pathname);
        }
        else
        { // relative to dirfd, resolve accordingly
            vfs_node_t node = current_task->fds[dirfd];
            if (!node)
                return (char *)-EBADF;
            if (node->type != file_dir)
                return (char *)-ENOTDIR;

            char *dirname = vfs_get_fullpath(node);

            char *prefix = vfs_get_fullpath(node->root);

            int prefixLen = strlen(prefix);
            int rootDirLen = strlen(dirname);
            int pathnameLen = strlen(pathname) + 1;

            char *out = malloc(prefixLen + rootDirLen + 1 + pathnameLen + 1);

            memcpy(out, prefix, prefixLen);
            memcpy(&out[prefixLen], dirname, rootDirLen);
            out[prefixLen + rootDirLen] = '/';
            memcpy(&out[prefixLen + rootDirLen + 1], pathname, pathnameLen);

            free(dirname);
            free(prefix);

            return out;
        }
    }

    return NULL;
}

uint64_t sys_open(const char *name, uint64_t flags, uint64_t mode)
{
    if (!name || check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return (uint64_t)-EBADF;
    }

    int create_mode = (flags & O_CREAT);

    // printk("Opening file %s\n", name);

    vfs_node_t node = vfs_open(name);
    if (!node && !create_mode)
    {
        return (uint64_t)-ENOENT;
    }

    if (!node)
    {
        int ret = 0;
        if (mode & O_DIRECTORY)
        {
            ret = vfs_mkdir(name);
        }
        else
        {
            ret = vfs_mkfile(name);
        }
        if (ret < 0)
            return (uint64_t)-ENOSPC;

        node = vfs_open(name);
        if (!node)
            return (uint64_t)-ENOENT;
    }

    node->flags = flags;

    current_task->fds[i] = node;

    return i;
}

uint64_t sys_openat(uint64_t dirfd, const char *name, uint64_t flags, uint64_t mode)
{
    if (!name || check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }
    char *path = at_resolve_pathname(dirfd, (char *)name);
    if (!path)
        return (uint64_t)-ENOMEM;

    uint64_t ret = sys_open(path, flags, mode);

    free(path);

    return ret;
}

uint64_t sys_close(uint64_t fd)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    current_task->fds[fd]->offset = 0;
    if (current_task->fds[fd]->lock.l_pid == current_task->pid)
    {
        current_task->fds[fd]->lock.l_type = F_UNLCK;
        current_task->fds[fd]->lock.l_pid = 0;
    }

    vfs_close(current_task->fds[fd]);

    current_task->fds[fd] = NULL;

    return 0;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len)
{
    if (!buf || check_user_overflow((uint64_t)buf, len))
    {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    if (current_task->fds[fd]->type & file_dir)
    {
        return (uint64_t)-EISDIR; // 读取目录时返回正确错误码
    }

    if (!buf)
    {
        return (uint64_t)-EFAULT;
    }

    ssize_t ret = vfs_read(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);

    if (ret > 0)
    {
        current_task->fds[fd]->offset += ret;
    }

    if (ret == -EAGAIN)
    {
        return (uint64_t)-EAGAIN; // 保持非阻塞I/O语义
    }

    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len)
{
    if (!buf || check_user_overflow((uint64_t)buf, len))
    {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    if (current_task->fds[fd]->type & file_dir)
    {
        return (uint64_t)-EISDIR; // 读取目录时返回正确错误码
    }

    if (!buf)
    {
        return (uint64_t)-EFAULT;
    }

    ssize_t ret = vfs_write(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);

    if (ret > 0)
    {
        current_task->fds[fd]->offset += ret;
    }

    if (ret == -EAGAIN)
    {
        return (uint64_t)-EAGAIN; // 保持非阻塞I/O语义
    }

    return ret;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    int64_t real_offset = offset;
    if (real_offset < 0 && current_task->fds[fd]->type & file_none && whence != SEEK_CUR)
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
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    return vfs_ioctl(current_task->fds[fd], cmd, arg);
}

uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count)
{
    if (!iovec || check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec)))
    {
        return (uint64_t)-EFAULT;
    }
    if ((uint64_t)iovec == 0)
    {
        return -EINVAL;
    }

    ssize_t total_read = 0;
    for (uint64_t i = 0; i < count; i++)
    {
        if (iovec[i].len == 0)
            continue;

        ssize_t ret = sys_read(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0)
        {
            return (uint64_t)ret;
        }
        total_read += ret;
        if ((size_t)ret < iovec[i].len)
            break;
    }
    return total_read;
}

uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count)
{
    if (!iovec || check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec)))
    {
        return (uint64_t)-EFAULT;
    }
    if ((uint64_t)iovec == 0)
    {
        return -EINVAL;
    }

    ssize_t total_written = 0;
    for (uint64_t i = 0; i < count; i++)
    {
        if (iovec[i].len == 0)
            continue;

        ssize_t ret = sys_write(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0)
        {
            return (uint64_t)ret;
        }
        total_written += ret;
        if ((size_t)ret < iovec[i].len)
            break;
    }
    return total_written;
}

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size)
{
    if (check_user_overflow(buf, size))
    {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (!current_task->fds[fd])
        return (uint64_t)-EBADF;
    if (current_task->fds[fd]->type != file_dir)
        return (uint64_t)-ENOTDIR;

    struct dirent *dents = (struct dirent *)buf;
    vfs_node_t node = current_task->fds[fd];

    uint64_t child_count = (uint64_t)list_length(node->child);

    int64_t max_dents_num = size / sizeof(struct dirent);

    int64_t read_count = 0;

    uint64_t offset = 0;
    list_foreach(node->child, i)
    {
        if (offset < node->offset)
            goto next;
        if (node->offset >= (child_count * sizeof(struct dirent)))
            break;
        if (read_count >= max_dents_num)
            break;
        vfs_node_t child_node = (vfs_node_t)i->data;
        dents[read_count].d_ino = child_node->inode;
        dents[read_count].d_off = node->offset;
        dents[read_count].d_reclen = sizeof(struct dirent);
        switch (child_node->type)
        {
        case file_dir:
            dents[read_count].d_type = DT_DIR;
            break;
        case file_none:
            dents[read_count].d_type = DT_REG;
            break;
        case file_symlink:
            dents[read_count].d_type = DT_LNK;
            break;
        default:
            dents[read_count].d_type = DT_UNKNOWN;
            break;
        }
        strncpy(dents[read_count].d_name, child_node->name, 1024);
        node->offset += sizeof(struct dirent);
        read_count++;
    next:
        offset += sizeof(struct dirent);
    }

    return read_count * sizeof(struct dirent);
}

uint64_t sys_chdir(const char *dirname)
{
    if (!dirname || check_user_overflow((uint64_t)dirname, strlen(dirname)))
    {
        return (uint64_t)-EFAULT;
    }
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
    if (!cwd || check_user_overflow((uint64_t)cwd, size))
    {
        return (uint64_t)-EFAULT;
    }
    char *str = vfs_get_fullpath(current_task->cwd);
    if (size < (uint64_t)strlen(str))
    {
        return (uint64_t)-ERANGE;
    }
    strncpy(cwd, str, size);
    free(str);
    return (uint64_t)strlen(str);
}

extern int unix_socket_fsid;
extern int unix_accept_fsid;

// Implement the sys_dup3 function
uint64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags)
{
    if (oldfd >= MAX_FD_NUM || current_task->fds[oldfd] == NULL)
    {
        return -EBADF;
    }

    if (newfd >= MAX_FD_NUM)
    {
        return -EBADF;
    }

    if (flags & ~O_CLOEXEC)
    {
        return -EINVAL;
    }

    if (oldfd == newfd)
    {
        return -EBADF;
    }

    if (current_task->fds[newfd] != NULL)
    {
        sys_close(newfd);
    }

    vfs_node_t new_node = vfs_dup(current_task->fds[oldfd]);
    if (new_node == NULL)
    {
        return -EMFILE;
    }

    current_task->fds[newfd] = new_node;

    if (flags & O_CLOEXEC)
    {
        new_node->flags |= O_CLOEXEC;
    }

    return newfd;
}

uint64_t sys_dup2(uint64_t fd, uint64_t newfd)
{
    vfs_node_t node = current_task->fds[fd];
    if (!node)
        return (uint64_t)-EBADF;

    vfs_node_t new = vfs_dup(node);
    if (!new)
        return (uint64_t)-ENOSPC;

    if (current_task->fds[newfd])
    {
        vfs_close(current_task->fds[newfd]);
    }
    current_task->fds[newfd] = new;

    return newfd;
}

uint64_t sys_dup(uint64_t fd)
{
    vfs_node_t node = current_task->fds[fd];
    if (!node)
        return (uint64_t)-EBADF;

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
        return (uint64_t)-EBADF;
    }

    return sys_dup2(fd, i);
}

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg)
{
    if (!current_task->fds[fd])
        return (uint64_t)-EBADF;

    switch (command)
    {
    case F_GETFD:
        return !!(current_task->fds[fd]->flags & O_CLOEXEC);
    case F_SETFD:
        return current_task->fds[fd]->flags |= O_CLOEXEC;
    case F_DUPFD_CLOEXEC:
        uint64_t newfd = sys_dup(fd);
        current_task->fds[newfd]->flags |= O_CLOEXEC;
        return newfd;
    case F_DUPFD:
        return sys_dup(fd);
    case F_GETFL:
        return current_task->fds[fd]->flags;
    case F_SETFL:
        uint32_t valid_flags = O_APPEND | O_DIRECT | O_NOATIME | O_NONBLOCK;
        current_task->fds[fd]->flags &= ~valid_flags;
        current_task->fds[fd]->flags |= arg & valid_flags;
        return 0;
    }

    return (uint64_t)-ENOSYS;
}

uint64_t sys_stat(const char *fd, struct stat *buf)
{
    vfs_node_t node = vfs_open(fd);
    if (!node)
    {
        return (uint64_t)-ENOENT;
    }

    buf->st_dev = 0;
    buf->st_ino = node->inode;
    buf->st_nlink = 1;
    buf->st_mode = node->mode | ((node->type & file_symlink) ? S_IFLNK : (node->type & file_dir ? S_IFDIR : S_IFREG));
    buf->st_uid = 0;
    buf->st_uid = 0;
    buf->st_gid = 0;
    if (node->type & file_stream)
    {
        buf->st_rdev = (4 << 8) | 1;
    }
    else if (node->type & file_fbdev)
    {
        buf->st_rdev = (29 << 8) | 0;
    }
    else if (node->type & file_keyboard)
    {
        buf->st_rdev = (13 << 8) | 0;
    }
    else if (node->type & file_mouse)
    {
        buf->st_rdev = (13 << 8) | 1;
    }
    else
    {
        buf->st_rdev = 0;
    }
    buf->st_blksize = node->blksz;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    vfs_close(node);

    return 0;
}

uint64_t sys_fstat(uint64_t fd, struct stat *buf)
{
    if (!buf || check_user_overflow((uint64_t)buf, sizeof(struct stat)))
    {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADF;
    }

    buf->st_dev = 0;
    buf->st_ino = current_task->fds[fd]->inode;
    buf->st_nlink = 1;
    buf->st_mode = current_task->fds[fd]->mode | ((current_task->fds[fd]->type & file_symlink) ? S_IFLNK : (current_task->fds[fd]->type & file_dir ? S_IFDIR : S_IFREG));
    buf->st_uid = 0;
    buf->st_gid = 0;
    if (current_task->fds[fd]->type & file_stream)
    {
        buf->st_rdev = (4 << 8) | 1;
    }
    else if (current_task->fds[fd]->type & file_fbdev)
    {
        buf->st_rdev = (29 << 8) | 0;
    }
    else if (current_task->fds[fd]->type & file_keyboard)
    {
        buf->st_rdev = (13 << 8) | 0;
    }
    else if (current_task->fds[fd]->type & file_mouse)
    {
        buf->st_rdev = (13 << 8) | 1;
    }
    else
    {
        buf->st_rdev = 0;
    }
    buf->st_blksize = current_task->fds[fd]->blksz;
    buf->st_size = current_task->fds[fd]->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    return 0;
}

uint64_t sys_newfstatat(uint64_t dirfd, const char *pathname, struct stat *buf, uint64_t flags)
{
    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);

    uint64_t ret = sys_stat(resolved, buf);

    free(resolved);

    return ret;
}

uint64_t sys_statx(uint64_t dirfd, const char *pathname, uint64_t flags, uint64_t mask, struct statx *buff)
{
    if (!pathname || check_user_overflow((uint64_t)pathname, strlen(pathname)))
    {
        return (uint64_t)-EFAULT;
    }
    if (!buff || check_user_overflow((uint64_t)buff, sizeof(struct statx)))
    {
        return (uint64_t)-EFAULT;
    }
    struct stat simple;
    memset(&simple, 0, sizeof(struct stat));
    uint64_t ret = sys_newfstatat(dirfd, pathname, &simple, flags);
    if ((int64_t)ret < 0)
        return ret;

    buff->stx_mask = mask;
    buff->stx_blksize = simple.st_blksize;
    buff->stx_attributes = 0;
    buff->stx_nlink = simple.st_nlink;
    buff->stx_uid = simple.st_uid;
    buff->stx_gid = simple.st_gid;
    buff->stx_mode = simple.st_mode;
    buff->stx_ino = simple.st_ino;
    buff->stx_size = simple.st_size;
    buff->stx_blocks = simple.st_blocks;
    buff->stx_attributes_mask = 0;

    buff->stx_atime.tv_sec = simple.st_atim.tv_sec;
    buff->stx_atime.tv_nsec = simple.st_atim.tv_nsec;

    buff->stx_btime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_btime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_ctime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_ctime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_mtime.tv_sec = simple.st_mtim.tv_sec;
    buff->stx_mtime.tv_nsec = simple.st_mtim.tv_nsec;

    // todo: special devices

    return 0;
}

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim)
{
    if (!lim || check_user_overflow((uint64_t)lim, sizeof(struct rlimit)))
    {
        return (uint64_t)-EFAULT;
    }
    *lim = current_task->rlim[resource];
    return 0;
}

uint64_t sys_prlimit64(uint64_t pid, int resource, const struct rlimit *new_rlim, struct rlimit *old_rlim)
{
    if (new_rlim && check_user_overflow((uint64_t)new_rlim, sizeof(struct rlimit)))
    {
        return (uint64_t)-EFAULT;
    }
    if (old_rlim)
    {
        uint64_t ret = sys_get_rlimit(resource, old_rlim);
        if (ret != 0)
            return ret;
    }

    if (new_rlim)
    {
        current_task->rlim[resource] = *new_rlim;
    }

    return 0;
}

uint32_t epoll_to_poll_comp(uint32_t epoll_events)
{
    uint32_t poll_events = 0;

    if (epoll_events & EPOLLIN)
        poll_events |= POLLIN;
    if (epoll_events & EPOLLOUT)
        poll_events |= POLLOUT;
    if (epoll_events & EPOLLPRI)
        poll_events |= POLLPRI;
    if (epoll_events & EPOLLERR)
        poll_events |= POLLERR;
    if (epoll_events & EPOLLHUP)
        poll_events |= POLLHUP;

    return poll_events;
}

uint32_t poll_to_epoll_comp(uint32_t poll_events)
{
    uint32_t epoll_events = 0;

    if (poll_events & POLLIN)
        epoll_events |= EPOLLIN;
    if (poll_events & POLLOUT)
        epoll_events |= EPOLLOUT;
    if (poll_events & POLLPRI)
        epoll_events |= EPOLLPRI;
    if (poll_events & POLLERR)
        epoll_events |= EPOLLERR;
    if (poll_events & POLLHUP)
        epoll_events |= EPOLLHUP;

    return epoll_events;
}

size_t sys_poll(struct pollfd *fds, int nfds, uint64_t timeout)
{
    int ready = 0;
    uint64_t start_time = nanoTime();

    bool sigexit = false;

    do
    {
        // 检查每个文件描述符
        for (int i = 0; i < nfds; i++)
        {
            fds[i].revents = 0;

            if (fds[i].fd > MAX_FD_NUM)
            {
                return (size_t)-EBADF;
            }
            vfs_node_t node = current_task->fds[fds[i].fd];
            if (!node)
                continue;
            if (!fs_callbacks[node->fsid]->poll)
            {
                if (fds[i].events & POLLIN || fds[i].events & POLLOUT)
                {
                    fds[i].revents = fds[i].events & POLLIN ? POLLIN : POLLOUT;
                    ready++;
                }
                continue;
            }
            int revents = epoll_to_poll_comp(vfs_poll(node, poll_to_epoll_comp(fds[i].events)));
            if (revents > 0)
            {
                fds[i].revents = revents;
                ready++;
            }
        }

        // sigexit = signals_pending_quick(current_task);

        if (ready > 0 || sigexit)
            break;

#if defined(__x86_64__)
        arch_enable_interrupt();
#endif

        arch_pause();
    } while (timeout != 0 && ((int)timeout == -1 || (nanoTime() - start_time) < timeout));

#if defined(__x86_64__)
    arch_disable_interrupt();
#endif

    if (!ready && sigexit)
        return (size_t)-EINTR;

    return ready;
}

uint64_t sys_ppoll(struct pollfd *fds, uint64_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask, size_t sigsetsize)
{
    if (!fds || check_user_overflow((uint64_t)fds, nfds * sizeof(struct pollfd)))
    {
        return (uint64_t)-EFAULT;
    }
    if (sigmask && sigsetsize < sizeof(sigset_t))
    {
        return (uint64_t)-EINVAL;
    }

    sigset_t origmask;
    if (sigmask)
    {
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);
    }

    int timeout = -1;
    if (timeout_ts)
    {
        timeout = timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000;
    }

    uint64_t ret = sys_poll(fds, nfds, timeout);

    if (sigmask)
    {
        sys_ssetmask(SIG_SETMASK, &origmask, NULL);
    }

    return ret;
}

static inline struct pollfd *select_add(struct pollfd **comp, size_t *compIndex,
                                        size_t *complength, int fd, int events)
{
    if ((*compIndex + 1) * sizeof(struct pollfd) >= *complength)
    {
        *complength *= 2;
        *comp = realloc(*comp, *complength);
    }

    (*comp)[*compIndex].fd = fd;
    (*comp)[*compIndex].events = events;
    (*comp)[*compIndex].revents = 0;

    return &(*comp)[(*compIndex)++];
}

// i hate this obsolete system call and do not plan on making it efficient
static inline bool select_bitmap(uint8_t *map, int index)
{
    int div = index / 8;
    int mod = index % 8;
    return map[div] & (1 << mod);
}

static inline void select_bitmap_set(uint8_t *map, int index)
{
    int div = index / 8;
    int mod = index % 8;
    map[div] |= 1 << mod;
}

size_t sys_select(int nfds, uint8_t *read, uint8_t *write, uint8_t *except,
                  struct timeval *timeout)
{
    if (read && check_user_overflow((uint64_t)read, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    if (write && check_user_overflow((uint64_t)write, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    if (except && check_user_overflow((uint64_t)except, sizeof(struct pollfd)))
    {
        return (size_t)-EFAULT;
    }
    size_t complength = sizeof(struct pollfd);
    struct pollfd *comp = (struct pollfd *)malloc(complength);
    size_t compIndex = 0;
    if (read)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(read, i))
                select_add(&comp, &compIndex, &complength, i, POLLIN);
        }
    }
    if (write)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(write, i))
                select_add(&comp, &compIndex, &complength, i, POLLOUT);
        }
    }
    if (except)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(except, i))
                select_add(&comp, &compIndex, &complength, i, POLLPRI | POLLERR);
        }
    }

    int toZero = (nfds + 8) / 8;
    if (read)
        memset(read, 0, toZero);
    if (write)
        memset(write, 0, toZero);
    if (except)
        memset(except, 0, toZero);

    size_t res = sys_poll(comp, compIndex, timeout ? (timeout->tv_sec * 1000 + (timeout->tv_usec + 1000) / 1000) : -1);

    if ((int64_t)res < 0)
    {
        free(comp);
        return res;
    }

    size_t verify = 0;
    for (size_t i = 0; i < compIndex; i++)
    {
        if (!comp[i].revents)
            continue;
        if (comp[i].events & POLLIN && comp[i].revents & POLLIN)
        {
            select_bitmap_set(read, comp[i].fd);
            verify++;
        }
        if (comp[i].events & POLLOUT && comp[i].revents & POLLOUT)
        {
            select_bitmap_set(write, comp[i].fd);
            verify++;
        }
        if ((comp[i].events & POLLPRI && comp[i].revents & POLLPRI) ||
            (comp[i].events & POLLERR && comp[i].revents & POLLERR))
        {
            select_bitmap_set(except, comp[i].fd);
            verify++;
        }
    }

    free(comp);
    return verify;
}

uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timespec *timeout, WeirdPselect6 *weirdPselect6)
{
    if (readfds && check_user_overflow((uint64_t)readfds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    if (writefds && check_user_overflow((uint64_t)writefds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    if (exceptfds && check_user_overflow((uint64_t)exceptfds, sizeof(fd_set) * nfds))
    {
        return (size_t)-EFAULT;
    }
    size_t sigsetsize = weirdPselect6->ss_len;
    sigset_t *sigmask = weirdPselect6->ss;

    if (sigsetsize < sizeof(sigset_t))
    {
        printk("weird sigset size\n");
        return (uint64_t)-EINVAL;
    }

    sigset_t origmask;
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);

    struct timeval timeoutConv;
    if (timeout)
    {
        timeoutConv = (struct timeval){.tv_sec = timeout->tv_sec,
                                       .tv_usec = (timeout->tv_nsec + 1000) / 1000};
    }
    else
    {
        timeoutConv = (struct timeval){.tv_sec = (uint64_t)-1,
                                       .tv_usec = (uint64_t)-1};
    }

    size_t ret = sys_select(nfds, (uint8_t *)readfds, (uint8_t *)writefds,
                            (uint8_t *)exceptfds, &timeoutConv);

    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, NULL);

    return ret;
}

size_t sys_access(char *filename, int mode)
{
    (void)mode;
    struct stat buf;
    return sys_stat(filename, &buf);
}

uint64_t sys_faccessat(uint64_t dirfd, const char *pathname, uint64_t mode)
{
    if (pathname[0] == '\0')
    { // by fd
        return 0;
    }
    if (check_user_overflow((uint64_t)pathname, strlen(pathname)))
    {
        return (uint64_t)-EFAULT;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname, uint64_t mode, uint64_t flags)
{
    if (pathname[0] == '\0')
    { // by fd
        return 0;
    }
    if (check_user_overflow((uint64_t)pathname, strlen(pathname)))
    {
        return (uint64_t)-EFAULT;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_link(const char *old, const char *new)
{
    if (check_user_overflow((uint64_t)old, strlen(old)))
    {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)new, strlen(new)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t old_node = vfs_open(old);
    if (!old_node)
    {
        return (uint64_t)-ENOENT;
    }

    int ret = 0;
    if (old_node->type & file_dir)
    {
        ret = vfs_mkdir(new);
        if (ret < 0)
        {
            return (uint64_t)-EEXIST;
        }
    }
    else
    {
        ret = vfs_mkfile(new);
        if (ret < 0)
        {
            return (uint64_t)-EEXIST;
        }
    }

    return 0;
}

uint64_t sys_readlink(char *path, char *buf, uint64_t size)
{
    if (path == NULL || buf == NULL || size == 0)
    {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)path, strlen(path)))
    {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)buf, size))
    {
        return (uint64_t)-EFAULT;
    }

    vfs_node_t node = vfs_open_at(current_task->cwd, path, true);
    if (node == NULL)
    {
        return (uint64_t)-ENOENT;
    }

    ssize_t result = vfs_readlink(node, buf, (size_t)size);
    vfs_close(node);

    if (result < 0)
    {
        switch (-result)
        {
        case 1:
            return (uint64_t)-ENOLINK;
        default:
            return (uint64_t)-EIO;
        }
    }

    return (uint64_t)result;
}

uint64_t sys_rmdir(const char *name)
{
    if (check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = vfs_open(name);
    if (!node)
        return -ENOENT;
    if (!(node->type & file_dir))
        return -EBADF;

    uint64_t ret = vfs_delete(node);

    return ret;
}

uint64_t sys_unlink(const char *name)
{
    if (check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = vfs_open(name);
    if (!node)
        return -ENOENT;

    uint64_t ret = vfs_delete(node);

    return ret;
}

uint64_t sys_unlinkat(uint64_t dirfd, const char *name, uint64_t flags)
{
    if (check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }
    char *path = at_resolve_pathname(dirfd, (char *)name);
    if (!path)
        return -ENOENT;

    uint64_t ret = sys_unlink((const char *)path);

    free(path);

    return ret;
}

vfs_node_t epollfs_root;
int epollfs_id;
int epollfd_id = 0;

// epoll API
size_t epoll_create1(int flags)
{
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

    char buf[256];
    sprintf(buf, "epoll%d", epollfd_id++);
    vfs_node_t node = vfs_node_alloc(epollfs_root, buf);
    node->type = file_epoll;
    epoll_t *epoll = malloc(sizeof(epoll_t));
    epoll->lock = false;
    epoll->firstEpollWatch = NULL;
    epoll->reference_count = 1;
    node->mode = 0700;
    node->handle = epoll;
    node->fsid = epollfs_id;

    current_task->fds[i] = node;

    return i;
}

uint64_t sys_epoll_create(int size)
{
    return epoll_create1(0);
}

uint64_t epoll_wait(vfs_node_t epollFd, struct epoll_event *events, int maxevents, int timeout)
{
    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    epoll_t *epoll = epollFd->handle;

    bool sigexit = false;

    int ready = 0;
    size_t target = nanoTime() + timeout;
    do
    {
        while (epoll->lock)
        {
            arch_pause();
        }

        epoll->lock = true;
        epoll_watch_t *browse = epoll->firstEpollWatch;

        while (browse && ready < maxevents)
        {
            int revents = vfs_poll(browse->fd, browse->watchEvents);
            if (revents != 0 && ready < maxevents)
            {
                events[ready].events = revents;
                events[ready].data = (epoll_data_t)browse->userlandData;
                ready++;
            }
            browse = browse->next;
        }

        epoll->lock = false;

        sigexit = signals_pending_quick(current_task);

        if (ready > 0 || sigexit)
            break;

#if defined(__x86_64__)
        arch_enable_interrupt();
#endif

        arch_pause();
    } while (timeout != 0 && (timeout == -1 || nanoTime() < target));

#if defined(__x86_64__)
    arch_disable_interrupt();
#endif

    if (!ready && sigexit)
        return (uint64_t)-EINTR;

    return ready;
}

size_t epoll_ctl(vfs_node_t epollFd, int op, int fd, struct epoll_event *event)
{
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_DEL && op != EPOLL_CTL_MOD)
        return (uint64_t)(-EINVAL);
    if (op & EPOLLET || op & EPOLLONESHOT || op & EPOLLEXCLUSIVE)
    {
        printk("bad opcode!\n"); // could atl do oneshot, but later
        return (uint64_t)(-ENOSYS);
    }

    epoll_t *epoll = epollFd->handle;
    if (!epoll)
        return -EINVAL;

    size_t ret = 0;

    vfs_node_t fdNode = current_task->fds[fd];
    if (!fdNode)
    {
        ret = (uint64_t)(-EBADF);
        goto cleanup;
    }

    switch (op)
    {
    case EPOLL_CTL_ADD:
    {
        epoll_watch_t *epollWatch = malloc(sizeof(epoll_watch_t));
        epollWatch->fd = fdNode;
        epollWatch->watchEvents = event->events;
        epollWatch->userlandData = (uint64_t)event->data.ptr;
        epollWatch->next = NULL;
        epoll_watch_t *current = epoll->firstEpollWatch;
        if (current)
        {
            while (current->next)
                current = current->next;
            current->next = epollWatch;
        }
        else
        {
            epoll->firstEpollWatch = epollWatch;
        }
        break;
    }
    case EPOLL_CTL_MOD:
    {
        epoll_watch_t *browse = epoll->firstEpollWatch;
        while (browse)
        {
            if (browse->fd == fdNode)
                break;
            browse = browse->next;
        }
        if (!browse)
        {
            ret = (uint64_t)(-ENOENT);
            goto cleanup;
        }
        browse->watchEvents = event->events;
        browse->userlandData = (uint64_t)event->data.ptr;
        break;
    }
    case EPOLL_CTL_DEL:
    {
        epoll_watch_t *browse = epoll->firstEpollWatch;
        epoll_watch_t *prev = NULL;
        while (browse)
        {
            if (browse->fd == fdNode)
                break;
            prev = browse;
            browse = browse->next;
        }
        if (!browse)
        {
            ret = (uint64_t)(-ENOENT);
            goto cleanup;
        }
        prev->next = browse->next;
        free(browse);
        break;
    }
    default:
        printk("[epoll] Unhandled opcode %d\n", op);
        break;
    }

cleanup:
    return ret;
}

size_t epoll_pwait(vfs_node_t epollFd, struct epoll_event *events, int maxevents,
                   int timeout, sigset_t *sigmask, size_t sigsetsize)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    if (sigsetsize < sizeof(sigset_t))
    {
        printk("weird sigset size\n");
        return (uint64_t)(-EINVAL);
    }

    sigset_t origmask;
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, sigmask, &origmask);
    size_t epollRet = epoll_wait(epollFd, events, maxevents, timeout);
    if (sigmask)
        sys_ssetmask(SIG_SETMASK, &origmask, 0);

    return epollRet;
}

uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_wait(node, events, maxevents, timeout);
}

uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (check_user_overflow((uint64_t)event, sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_ctl(node, op, fd, event);
}

uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout, sigset_t *sigmask,
                         size_t sigsetsize)
{
    if (check_user_overflow((uint64_t)events, maxevents * sizeof(struct epoll_event)))
    {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_pwait(node, events, maxevents, timeout, sigmask, sigsetsize);
}

uint64_t sys_epoll_create1(int flags) { return epoll_create1(flags); }

bool epollfs_close(void *current)
{
    epoll_t *epoll = current;
    epoll->reference_count--;
    // if (!epoll->reference_count)
    //     return true;
    return false;
}

static vfs_node_t eventfdfs_root = NULL;
static int eventfdfs_id = 0;

uint64_t sys_eventfd2(uint64_t initial_val, uint64_t flags)
{
    // 参数校验
    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE))
        return (uint64_t)-EINVAL;

    // 分配文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fds[i])
        {
            fd = i;
            break;
        }
    }

    if (fd == -1)
    {
        return (uint64_t)-EMFILE;
    }

    // 分配eventfd结构体
    eventfd_t *efd = malloc(sizeof(eventfd_t));
    if (!efd)
        return (uint64_t)-ENOMEM;

    efd->count = initial_val;
    efd->flags = flags;

    // 创建VFS节点
    char buf[256];
    sprintf(buf, "eventfd%d", eventfd_id++);
    vfs_node_t node = vfs_node_alloc(eventfdfs_root, buf);
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = eventfdfs_id;
    node->handle = efd;

    current_task->fds[fd] = node;

    return fd;
}

static int signalfd_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

// 实现读写操作
static ssize_t eventfd_read(vfs_node_t node, void *buf, size_t offset, size_t len)
{
    eventfd_t *efd = node->handle;
    uint64_t value;

    while (efd->count == 0)
    {
        if (efd->flags & EFD_NONBLOCK)
            return -EAGAIN;

        arch_enable_interrupt();

        arch_pause();
    }

    value = (efd->flags & EFD_SEMAPHORE) ? 1 : efd->count;
    memcpy(buf, &value, sizeof(uint64_t));

    efd->count -= value;
    return sizeof(uint64_t);
}

static ssize_t eventfd_write(vfs_node_t node, const void *buf, size_t offset, size_t len)
{
    eventfd_t *efd = node->handle;
    uint64_t value;
    memcpy(&value, buf, sizeof(uint64_t));

    if (UINT64_MAX - efd->count < value)
        return -EINVAL;

    efd->count += value;

    return sizeof(uint64_t);
}

static int eventfd_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

static int epoll_poll(void *file, size_t event)
{
    return -EOPNOTSUPP;
}

static vfs_node_t signalfdfs_root = NULL;
static int signalfdfs_id = 0;
static int signalfd_id = 0;

// 新增文件操作函数
static ssize_t signalfd_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    struct signalfd_ctx *ctx = data;

    while (ctx->queue_head == ctx->queue_tail)
    {
#if defined(__x86_64__)
        arch_enable_interrupt();
#endif

        arch_pause();
    }

#if defined(__x86_64__)
    arch_disable_interrupt();
#endif

    struct sigevent *ev = &ctx->queue[ctx->queue_tail];
    size_t copy_len = len < sizeof(*ev) ? len : sizeof(*ev);
    memcpy(buf, ev, copy_len);

    ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
    return copy_len;
}

static int signalfd_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    struct signalfd_ctx *ctx = data;
    switch (cmd)
    {
    case SIGNALFD_IOC_MASK:
        memcpy(&ctx->sigmask, (sigset_t *)arg, sizeof(sigset_t));
        return 0;
    default:
        return -ENOTTY;
    }
}

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask, int flags)
{
    if (sizemask != sizeof(sigset_t))
        return -EINVAL;

    struct signalfd_ctx *ctx = malloc(sizeof(struct signalfd_ctx));
    if (!ctx)
        return -ENOMEM;

    memcpy(&ctx->sigmask, mask, sizeof(sigset_t));

    ctx->queue_size = 32;
    ctx->queue = malloc(ctx->queue_size * sizeof(struct sigevent));
    ctx->queue_head = ctx->queue_tail = 0;

    // 分配文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fds[i])
        {
            fd = i;
            break;
        }
    }

    // 创建VFS节点
    char buf[256];
    sprintf(buf, "signalfd%d", signalfd_id++);
    vfs_node_t node = vfs_node_alloc(signalfdfs_root, buf);
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = signalfdfs_id;
    node->handle = ctx;
    current_task->fds[fd] = node;

    return fd;
}

uint64_t sys_signalfd(int ufd, const sigset_t *mask, size_t sizemask)
{
    return sys_signalfd4(ufd, mask, sizemask, 0);
}

uint64_t sys_rename(const char *old, const char *new)
{
    vfs_node_t node = vfs_open(old);
    int ret = vfs_rename(node, new);
    if (ret < 0)
        return -ENOENT;

    return 0;
}

uint64_t sys_fchdir(uint64_t fd)
{
    if (fd >= MAX_FD_NUM || !current_task->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fds[fd];
    if (node->type != file_dir)
        return -ENOTDIR;

    current_task->cwd = node;

    return 0;
}

int timerfdfs_id = 0;
static vfs_node_t timerfdfs_root = NULL;

static int timerfd_id = 0;

int sys_timerfd_create(int clockid, int flags)
{
    // 参数检查
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    // 分配文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fds[i])
        {
            fd = i;
            break;
        }
    }
    if (fd == -1)
        return -EMFILE;

    timerfd_t *tfd = malloc(sizeof(timerfd_t));
    memset(tfd, 0, sizeof(timerfd_t));
    tfd->timer.clock_type = clockid;
    tfd->flags = flags;

    char buf[32];
    sprintf(buf, "timerfd%d", timerfd_id++);
    vfs_node_t node = vfs_node_alloc(timerfdfs_root, buf);
    node->type = file_stream;
    node->fsid = timerfdfs_id;
    node->handle = tfd;

    current_task->fds[fd] = node;

    return fd;
}

int sys_timerfd_settime(int fd, int flags, const struct itimerval *new_value, struct itimerval *old_value)
{
    if (fd >= MAX_FD_NUM || !current_task->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fds[fd];
    timerfd_t *tfd = node->handle;

    if (old_value)
    {
        uint64_t remaining = tfd->timer.expires > jiffies ? tfd->timer.expires - jiffies : 0;

        old_value->it_interval.tv_sec = tfd->timer.interval / 1000;
        old_value->it_interval.tv_usec = (tfd->timer.interval % 1000) * 1000;

        old_value->it_value.tv_sec = remaining / 1000;
        old_value->it_value.tv_usec = (remaining % 1000) * 1000;
    }

    uint64_t interval = new_value->it_interval.tv_sec * 1000 +
                        new_value->it_interval.tv_usec / 1000000;
    uint64_t expires = new_value->it_value.tv_sec * 1000 +
                       new_value->it_value.tv_usec / 1000000;

    tfd->timer.interval = interval;
    tfd->timer.expires = jiffies + expires;

    return 0;
}

bool sys_timerfd_close(void *current)
{
    free(current);
    return true;
}

static int dummy()
{
    return -ENOSYS;
}

vfs_node_t signalfd_dup(vfs_node_t node)
{
    if (!node || !node->handle)
        return NULL;

    struct signalfd_ctx *ctx = node->handle;

    // 创建新的vfs节点
    vfs_node_t new_node = vfs_node_alloc(node->parent, node->name);
    if (!new_node)
        return NULL;

    // 复制节点属性
    memcpy(new_node, node, sizeof(struct vfs_node));

    // 创建新的上下文
    struct signalfd_ctx *new_ctx = malloc(sizeof(struct signalfd_ctx));
    if (!new_ctx)
    {
        vfs_free(new_node);
        return NULL;
    }

    // 复制上下文
    memcpy(new_ctx, ctx, sizeof(struct signalfd_ctx));
    new_node->handle = new_ctx;

    // 复制信号队列
    new_ctx->queue = malloc(new_ctx->queue_size * sizeof(struct sigevent));
    memcpy(new_ctx->queue, ctx->queue, new_ctx->queue_size * sizeof(struct sigevent));

    return new_node;
}

vfs_node_t epollfd_dup(vfs_node_t node)
{
    if (!node || !node->handle)
        return NULL;

    epoll_t *epoll = node->handle;

    // 创建新的vfs节点
    vfs_node_t new_node = vfs_node_alloc(node->parent, node->name);
    if (!new_node)
        return NULL;

    // 复制节点属性
    memcpy(new_node, node, sizeof(struct vfs_node));

    // 创建新的epoll上下文
    epoll_t *new_epoll = malloc(sizeof(epoll_t));
    if (!new_epoll)
    {
        vfs_free(new_node);
        return NULL;
    }

    // 初始化新epoll
    new_epoll->lock = false;
    new_epoll->reference_count = 1;
    new_epoll->firstEpollWatch = NULL;
    new_node->handle = new_epoll;

    // 复制所有监视项
    epoll_watch_t *current = epoll->firstEpollWatch;
    epoll_watch_t **last = &new_epoll->firstEpollWatch;

    while (current)
    {
        epoll_watch_t *new_watch = malloc(sizeof(epoll_watch_t));
        memcpy(new_watch, current, sizeof(epoll_watch_t));
        *last = new_watch;
        last = &new_watch->next;
        current = current->next;
    }

    return new_node;
}

vfs_node_t eventfd_dup(vfs_node_t node)
{
    if (!node || !node->handle)
        return NULL;

    eventfd_t *efd = node->handle;

    // 创建新的vfs节点
    vfs_node_t new_node = vfs_node_alloc(node->parent, node->name);
    if (!new_node)
        return NULL;

    // 复制节点属性
    memcpy(new_node, node, sizeof(struct vfs_node));

    // 创建新的eventfd上下文
    eventfd_t *new_efd = malloc(sizeof(eventfd_t));
    if (!new_efd)
    {
        vfs_free(new_node);
        return NULL;
    }

    // 复制上下文
    memcpy(new_efd, efd, sizeof(eventfd_t));
    new_node->handle = new_efd;

    return new_node;
}

vfs_node_t timerfd_dup(vfs_node_t node)
{
    if (!node || !node->handle)
        return NULL;

    timerfd_t *tfd = node->handle;

    // 创建新的vfs节点
    vfs_node_t new_node = vfs_node_alloc(node->parent, node->name);
    if (!new_node)
        return NULL;

    // 复制节点属性
    memcpy(new_node, node, sizeof(struct vfs_node));

    // 创建新的timerfd上下文
    timerfd_t *new_tfd = malloc(sizeof(timerfd_t));
    if (!new_tfd)
    {
        vfs_free(new_node);
        return NULL;
    }

    // 复制上下文
    memcpy(new_tfd, tfd, sizeof(timerfd_t));
    new_node->handle = new_tfd;

    return new_node;
}

static struct vfs_callback epoll_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = epollfs_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = epoll_poll,
    .dup = (vfs_dup_t)epollfd_dup,
};

static struct vfs_callback eventfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)eventfd_read,
    .write = (vfs_write_t)eventfd_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = eventfd_poll,
    .dup = (vfs_dup_t)eventfd_dup,
};

static struct vfs_callback signalfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)signalfd_read,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)signalfd_ioctl,
    .poll = signalfd_poll,
    .dup = (vfs_dup_t)eventfd_dup,
};

static struct vfs_callback timerfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)sys_timerfd_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .dup = (vfs_dup_t)timerfd_dup,
};

void fs_syscall_init()
{
    epollfs_id = vfs_regist("epollfs", &epoll_callbacks);
    epollfs_root = vfs_node_alloc(rootdir, "epoll");
    epollfs_root->type = file_dir;
    epollfs_root->mode = 0644;
    epollfs_root->fsid = epollfs_id;

    eventfdfs_id = vfs_regist("eventfdfs", &eventfd_callbacks);
    eventfdfs_root = vfs_node_alloc(rootdir, "event");
    eventfdfs_root->type = file_dir;
    eventfdfs_root->mode = 0644;
    eventfdfs_root->fsid = eventfdfs_id;

    signalfdfs_id = vfs_regist("signalfdfs", &signalfd_callbacks);
    signalfdfs_root = vfs_node_alloc(rootdir, "signal");
    signalfdfs_root->type = file_dir;
    signalfdfs_root->mode = 0644;
    signalfdfs_root->fsid = signalfdfs_id;

    timerfdfs_id = vfs_regist("timerfd", &timerfd_callbacks);
    timerfdfs_root = vfs_node_alloc(rootdir, "timer");
    timerfdfs_root->type = file_dir;
    timerfdfs_root->mode = 0644;
    timerfdfs_root->fsid = timerfdfs_id;
}

uint64_t sys_flock(int fd, uint64_t operation)
{
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fds[fd];
    struct flock *lock = &node->lock;
    uint64_t pid = current_task->pid;

    // 提前检查参数有效性
    switch (operation & ~LOCK_NB)
    {
    case LOCK_SH:
    case LOCK_EX:
    case LOCK_UN:
        break;
    default:
        return -EINVAL;
    }

    // 非阻塞模式下立即检查冲突
    if (operation & LOCK_NB)
    {
        if ((operation & LOCK_SH) && lock->l_type == F_WRLCK)
            return -EWOULDBLOCK;
        if ((operation & LOCK_EX) && lock->l_type != F_UNLCK)
            return -EWOULDBLOCK;
    }

    // 实际加锁逻辑
    switch (operation & ~LOCK_NB)
    {
    case LOCK_SH:
    case LOCK_EX:
        while (lock->l_type != F_UNLCK && lock->l_pid != pid)
        {
            if (operation & LOCK_NB)
                return -EWOULDBLOCK;

            while (lock->lock)
            {
#if defined(__x86_64__)
                arch_enable_interrupt();
#endif

                arch_pause();
            }

#if defined(__x86_64__)
            arch_disable_interrupt();
#endif
        }
        lock->l_type = (operation & LOCK_EX) ? F_WRLCK : F_RDLCK;
        lock->l_pid = pid;
        break;

    case LOCK_UN:
        if (lock->l_pid != pid)
            return -EACCES;
        lock->l_type = F_UNLCK;
        lock->l_pid = 0;
        lock->lock = 1;
        break;
    }

    return 0;
}

uint64_t sys_mkdir(const char *name, uint64_t mode)
{
    if (check_user_overflow((uint64_t)name, strlen(name)))
    {
        return (uint64_t)-EFAULT;
    }
    int ret = vfs_mkdir(name);
    if (ret < 0)
    {
        return (uint64_t)-EEXIST;
    }
    return 0;
}

void wake_blocked_tasks(task_block_list_t *head)
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
