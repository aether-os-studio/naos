#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <net/socket.h>

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
            return pathname;
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

    return 0;
}

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
    if (!node && !(mode & O_CREAT))
    {
        return (uint64_t)-ENOENT;
    }

    if (!node)
    {
        int ret = vfs_mkfile(name);
        if (ret < 0)
            return (uint64_t)-ENOENT;

        node = vfs_open(name);
        if (!node)
        {
            printk("Cannot create file: %s\n", name);
            return (uint64_t)-ENOENT;
        }
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

    if (node->type != file_dir)
    {
        return (uint64_t)-ENOTDIR;
    }

    int64_t max_dents_num = size / sizeof(struct dirent);

    int64_t read_count = 0;

    list_foreach(node->child, i)
    {
        if (node->offset >= list_length(node->child))
            break;
        if (read_count >= max_dents_num)
            break;
        vfs_node_t child_node = (vfs_node_t)i->data;
        dents[read_count].d_ino = 0;
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
        default:
            dents[read_count].d_type = DT_UNKNOWN;
            break;
        }
        strncpy(dents[read_count].d_name, child_node->name, 1024);
        node->offset += sizeof(struct dirent);
        read_count++;
    }

    return read_count * sizeof(struct dirent);
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
    if (size < (uint64_t)strlen(str))
    {
        return (uint64_t)-ERANGE;
    }
    strncpy(cwd, str, size);
    free(str);
    return (uint64_t)strlen(str);
}

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg)
{
    (void)fd;
    (void)arg;

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

uint64_t sys_stat(const char *fd, struct stat *buf)
{
    static uint64_t i = 0;

    vfs_node_t node = vfs_open(fd);
    if (!node)
    {
        return (uint64_t)-ENOENT;
    }

    buf->st_dev = 0;
    buf->st_ino = i++;
    buf->st_nlink = 1;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_rdev = 0;
    buf->st_blksize = DEFAULT_PAGE_SIZE;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    return 0;
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

size_t sys_poll(struct pollfd *fds, int nfds, int timeout)
{
    int ready = 0;
    uint32_t start_time = nanoTime();

    while (1)
    {
        // 检查每个文件描述符
        for (int i = 0; i < nfds; i++)
        {
            fds[i].revents = 0;

            if (fds[i].fd == 0 && (fds[i].events & POLLIN))
            {
#if defined(__x86_64__)
                if (kb_fifo.p_head != kb_fifo.p_tail)
                {
                    uint8_t temp = 0;
                    if (kb_fifo.shift)
                        temp = keyboard_code1[*kb_fifo.p_tail];
                    else
                        temp = keyboard_code[*kb_fifo.p_tail];

                    if (*kb_fifo.p_tail == 28 || *kb_fifo.p_tail == 15 || temp != 0)
                    {
                        fds[i].revents |= POLLIN;
                        ready++;
                    }
                }
#endif
            }
        }

        if (ready > 0)
        {
            return ready;
        }

        if (timeout >= 0)
        {
            uint32_t current_time = nanoTime();
            if (current_time - start_time >= (uint32_t)timeout)
            {
                return 0; // 超时返回
            }
        }

        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

    return ready;
}

static inline struct pollfd *select_add(struct pollfd **comp, size_t *compIndex,
                                        size_t *compLength, int fd, int events)
{
    if ((*compIndex + 1) * sizeof(struct pollfd) >= *compLength)
    {
        *compLength *= 2;
        *comp = realloc(*comp, *compLength);
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
    size_t compLength = sizeof(struct pollfd);
    struct pollfd *comp = (struct pollfd *)malloc(compLength);
    size_t compIndex = 0;
    if (read)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(read, i))
                select_add(&comp, &compIndex, &compLength, i, POLLIN);
        }
    }
    if (write)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(write, i))
                select_add(&comp, &compIndex, &compLength, i, POLLOUT);
        }
    }
    if (except)
    {
        for (int i = 0; i < nfds; i++)
        {
            if (select_bitmap(except, i))
                select_add(&comp, &compIndex, &compLength, i, POLLPRI | POLLERR);
        }
    }

    int toZero = (nfds + 8) / 8;
    if (read)
        memset(read, 0, toZero);
    if (write)
        memset(write, 0, toZero);
    if (except)
        memset(except, 0, toZero);

    size_t res = sys_poll(
        comp, compIndex,
        timeout ? (timeout->tv_sec * 1000 + (timeout->tv_usec + 1000) / 1000)
                : -1);

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

    // nope, we need to report individual events!
    // assert(verify == res);
    // nope, POLLERR & POLLPRI don't need validation sooo yeah!
    // assert(verify >= res);
    free(comp);
    return verify;
}

uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timespec *timeout, WeirdPselect6 *weirdPselect6)
{
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

    struct timeval timeoutConv = {.tv_sec = timeout->tv_sec,
                                  .tv_usec = (timeout->tv_nsec + 1000) / 1000};

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

    char *resolved = at_resolve_pathname(dirfd, pathname);
    if ((size_t)resolved < 0)
        return (uint64_t)resolved;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}
