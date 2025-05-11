#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <net/socket.h>

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

    return NULL;
}

uint64_t sys_open(const char *name, uint64_t flags, uint64_t mode)
{
    if (!name)
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
        return (uint64_t)-EBADFD;
    }

    // 新增标志位检查
    int create_mode = (flags & O_CREAT);
    int excl_mode = (flags & O_EXCL);

    // 处理 O_EXCL 标志
    if (create_mode && excl_mode)
    {
        vfs_node_t exist_check = vfs_open(name);
        if (exist_check)
        {
            vfs_close(exist_check);
            return (uint64_t)-EEXIST;
        }
    }

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
        // 创建文件/目录的逻辑
        if (ret < 0)
            return (uint64_t)-ENOENT;

        node = vfs_open(name);
        if (!node)
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

    current_task->fds[fd]->offset = 0;
    if (current_task->fds[fd]->type == file_pipe && current_task->fds[fd]->handle)
    {
        pipe_t *pipe = current_task->fds[fd]->handle;
        pipe->reference_count--;
    }

    if (current_task->fds[fd]->lock.l_pid == current_task->pid)
    {
        current_task->fds[fd]->lock.l_type = F_UNLCK;
        current_task->fds[fd]->lock.l_pid = 0;
    }

    if (current_task->fds[fd]->type != file_socket)
    {
        vfs_close(current_task->fds[fd]);
    }

    current_task->fds[fd] = NULL;

    return 0;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    ssize_t ret = vfs_read(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
    sys_lseek(fd, ret, SEEK_CUR);
    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    ssize_t ret = vfs_write(current_task->fds[fd], buf, current_task->fds[fd]->offset, len);
    sys_lseek(fd, ret, SEEK_CUR);
    return ret;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence)
{
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
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
    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
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
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (!current_task->fds[fd])
        return (uint64_t)-EBADF;
    if (current_task->fds[fd]->type != file_dir)
        return (uint64_t)-ENOTDIR;

    struct dirent *dents = (struct dirent *)buf;
    vfs_node_t node = current_task->fds[fd];

    int64_t max_dents_num = size / sizeof(struct dirent);

    int64_t read_count = 0;

    list_foreach(node->child, i)
    {
        if (node->offset >= ((uint64_t)list_length(node->child) * sizeof(struct dirent)))
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
        return (uint64_t)-EBADFD;
    }

    char *fullpath = vfs_get_fullpath(node);
    vfs_node_t new = vfs_open(fullpath);
    free(fullpath);

    current_task->fds[i] = new;

    return i;
}

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg)
{
    (void)arg;

    switch (command)
    {
    case F_GETFD:
        return 0;
    case F_SETFD:
        return 0;
    case F_DUPFD_CLOEXEC:
    case F_DUPFD:
        return sys_dup(fd);
    case F_GETFL:
        return 0;
        break;
    case F_SETFL:
        return 0;
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
    buf->st_mode = 0700 | (node->type == file_dir ? S_IFDIR : S_IFREG);
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_rdev = (node->type == file_stream) ? ((4 << 8) | 1) : 0;
    buf->st_blksize = DEFAULT_PAGE_SIZE;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    vfs_close(node);

    return 0;
}

uint64_t sys_fstat(uint64_t fd, struct stat *buf)
{
    static uint64_t i = 0;

    if (fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return (uint64_t)-EBADFD;
    }

    buf->st_dev = 0;
    buf->st_ino = i++;
    buf->st_nlink = 1;
    buf->st_mode = 0700 | (current_task->fds[fd]->type == file_dir ? S_IFDIR : S_IFREG);
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_rdev = (current_task->fds[fd]->type == file_stream) ? ((4 << 8) | 1) : 0;
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

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_link(const char *old, const char *new)
{
    vfs_node_t old_node = vfs_open(old);
    if (!old_node)
    {
        return (uint64_t)-ENOENT;
    }

    int ret = 0;
    if (old_node->type == file_dir)
    {
        ret = vfs_mkdir(new);
        if (ret < 0)
        {
            return (uint64_t)-ENOENT;
        }
    }
    else
    {
        ret = vfs_mkfile(new);
        if (ret < 0)
        {
            return (uint64_t)-ENOENT;
        }
    }

    return 0;
}

// todo
uint64_t sys_readlink(char *path, char *buf, uint64_t size)
{
    vfs_node_t node = vfs_open((const char *)path);
    if (!node)
        return (uint64_t)-ENOENT;

    ssize_t len = 0;
    if (node->type == file_dir)
    {
        strncpy(buf, (const char *)path, size);
        len = size;
        goto ok;
    }
    else
    {
        len = vfs_read(node, buf, 0, size);
    }

ok:
    vfs_close(node);

    return len;
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
        return -EBADFD;
    }

    epoll_t *epoll = malloc(sizeof(epoll_t));
    epoll->timesOpened = 1;
    epoll->firstEpollWatch = NULL;

    char buf[256];
    sprintf(buf, "epoll%d", epollfd_id++);
    vfs_node_t node = vfs_node_alloc(epollfs_root, buf);
    node->type = file_none;
    node->handle = epoll;
    node->fsid = epollfs_id;

    current_task->fds[i] = node;

    return i;
}

uint64_t sys_epoll_create(int size)
{
    return epoll_create1(0);
}

// if this doesn't give you enough cues as to why you NEED to avoid the kernel
// shell at all costs then idk what does. the reason this exists btw is for
// bash's readline to not freak out over pselect6()
bool ioSwitch = false;

int internal_poll_handler(vfs_node_t fd, int events)
{
    int revents = 0;
    if (events & EPOLLIN && ioSwitch)
        revents |= EPOLLIN;
    if (events & EPOLLOUT)
        revents |= EPOLLOUT;
    ioSwitch = !ioSwitch;
    return revents;
}

uint64_t epoll_wait(vfs_node_t epollFd, struct epoll_event *events, int maxevents,
                    int timeout)
{
    if (maxevents < 1)
        return (uint64_t)-EINVAL;
    epoll_t *epoll = epollFd->handle;

    bool sigexit = false;

    // hack'y way but until I implement wake queues, it is what it is
    int ready = 0;
    size_t target = nanoTime() + timeout;
    do
    {
        epoll_watch_t *browse = epoll->firstEpollWatch;
        while (browse && ready < maxevents)
        {
            int revents =
                internal_poll_handler(browse->fd, browse->watchEvents);
            if (revents != 0 && ready < maxevents)
            {
                events[ready].events = revents;
                events[ready].data = (epoll_data_t)browse->userlandData;
                ready++;
            }
            browse = browse->next;
        }

        arch_enable_interrupt();

        arch_pause();
    } while (timeout != 0 && (timeout == -1 || nanoTime() < target));

    arch_disable_interrupt();

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

    size_t ret = 0;

    vfs_node_t fdNode = epollFd;
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
        epollWatch->next = epoll->firstEpollWatch;
        epoll->firstEpollWatch = epollWatch;
        epollWatch->fd = fdNode;
        epollWatch->watchEvents = event->events;
        epollWatch->userlandData = (uint64_t)event->data.ptr;
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
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_wait(node, events, maxevents, timeout);
}

uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_ctl(node, op, fd, event);
}

uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout, sigset_t *sigmask,
                         size_t sigsetsize)
{
    vfs_node_t node = current_task->fds[epfd];
    if (!node)
        return (uint64_t)-EBADF;
    return epoll_pwait(node, events, maxevents, timeout, sigmask, sigsetsize);
}

uint64_t sys_epoll_create1(int flags) { return epoll_create1(flags); }

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
    node->type = file_stream;
    node->fsid = eventfdfs_id;
    node->handle = efd;

    current_task->fds[fd] = node;

    return fd;
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

static vfs_node_t signalfdfs_root = NULL;
static int signalfdfs_id = 0;
static int signalfd_id = 0;

// 新增文件操作函数
static ssize_t signalfd_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    struct signalfd_ctx *ctx = data;

    while (ctx->queue_head == ctx->queue_tail)
    {
        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

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

static void dummy() {}

static struct vfs_callback epoll_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = dummy,
    .write = dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
};

static struct vfs_callback eventfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = eventfd_read,
    .write = eventfd_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
};

static struct vfs_callback signalfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = signalfd_read,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)signalfd_ioctl,
};

void epoll_init()
{
    epollfs_id = vfs_regist("epollfs", &epoll_callbacks);
    epollfs_root = vfs_node_alloc(rootdir, "epoll");
    epollfs_root->type = file_dir;

    eventfdfs_id = vfs_regist("eventfdfs", &eventfd_callbacks);
    eventfdfs_root = vfs_node_alloc(rootdir, "eventfd");
    eventfdfs_root->type = file_dir;

    signalfdfs_id = vfs_regist("signalfdfs", &signalfd_callbacks);
    signalfdfs_root = vfs_node_alloc(rootdir, "signalfd");
    signalfdfs_root->type = file_dir;
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
                arch_enable_interrupt();

                arch_pause();
            }

            arch_disable_interrupt();
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
