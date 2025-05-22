#include <arch/arch.h>
#include <net/net_syscall.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

extern socket_op_t socket_ops;
extern socket_op_t accept_ops;

vfs_node_t sockfs_root = NULL;

static int sockfsfd_id = 0;

socket_t first_unix_socket;

socket_t sockets[MAX_SOCKETS];

int unix_socket_fsid = 0;
int unix_accept_fsid = 0;

char *unix_socket_addr_safe(const struct sockaddr_un *addr, size_t len)
{
    if (addr->sun_family != 1)
        return (void *)-(EAFNOSUPPORT);

    size_t addrLen = len - sizeof(addr->sun_family);
    if (addrLen <= 0)
        return (void *)-(EINVAL);

    char *safe = calloc(addrLen + 1, 1); // ENSURE there's a null char
    bool abstract = addr->sun_path[0] == '\0';
    int skip = abstract ? 1 : 0;

    if (abstract)
    {
        char *new_safe = realloc(safe, addrLen + 2);
        if (new_safe == NULL)
        {
            free(safe);
            return (void *)-(ENOMEM);
        }
        safe = new_safe;
        safe[0] = '@'; // 使用 @ 作为抽象 socket 地址的前缀
        memcpy(safe + 1, &addr->sun_path[skip], addrLen - skip);
    }
    else
    {
        memcpy(safe, &addr->sun_path[skip], addrLen - skip);
    }

    return safe;
}

vfs_node_t unix_socket_accept_create(unix_socket_pair_t *dir)
{
    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_child_append(sockfs_root, buf, NULL);
    socknode->type = file_none;
    socknode->type = 0755;

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    handle->op = &accept_ops;

    socknode->handle = handle;
    socknode->fsid = unix_accept_fsid;

    return socknode;
}

// bool unix_socket_acceptDuplicate(vfs_node_t original, vfs_node_t orphan)
// {
//     orphan->handle = original->handle;
//     unix_socket_pair_t *pair = original->handle;
//     pair->serverFds++;

//     return true;
// }

unix_socket_pair_t *unix_socket_allocate_pair()
{
    unix_socket_pair_t *pair = calloc(sizeof(unix_socket_pair_t), 1);
    pair->clientBuffSize = BUFFER_SIZE;
    pair->serverBuffSize = BUFFER_SIZE;
    pair->serverBuff = malloc(pair->serverBuffSize);
    pair->clientBuff = malloc(pair->clientBuffSize);
    return pair;
}

void unix_socket_free_pair(unix_socket_pair_t *pair)
{
    free(pair->clientBuff);
    free(pair->serverBuff);
    free(pair->filename);
    free(pair);
}

void socket_accept_close(void *current)
{
    socket_handle_t *handle = current;
    unix_socket_pair_t *pair = handle->sock;
    pair->serverFds--;

    if (pair->serverFds == 0 && pair->clientFds == 0)
        unix_socket_free_pair(pair);
}

void socket_socket_close(socket_handle_t *socket_handle)
{
    socket_t *unixSocket = socket_handle->sock;
    unixSocket->timesOpened--;
    if (unixSocket->pair)
    {
        unixSocket->pair->clientFds--;
        if (!unixSocket->pair->clientFds && !unixSocket->pair->serverFds)
            unix_socket_free_pair(unixSocket->pair);
    }
    if (unixSocket->timesOpened == 0)
    {
        socket_t *browse = &first_unix_socket;

        while (browse->next != unixSocket)
        {
            browse = browse->next;
        }

        browse->next = unixSocket->next;
        free(unixSocket);
    }
}

size_t unix_socket_accept_recv_from(vfs_node_t fd, uint8_t *out, size_t limit,
                                    int flags, struct sockaddr_un *addr,
                                    uint32_t *len)
{
    (void)addr;
    (void)len;

    socket_handle_t *handle = fd->handle;
    unix_socket_pair_t *pair = handle->sock;
    if (!pair->clientFds && pair->serverBuffPos == 0)
        return 0;
    while (true)
    {
        if (!pair->clientFds && pair->serverBuffPos == 0)
        {
            return 0;
        }
        else if ((fd->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 pair->serverBuffPos == 0)
        {
            return -(EWOULDBLOCK);
        }
        else if (pair->serverBuffPos > 0)
            break;
    }

    // spinlock already acquired
    size_t toCopy = MIN(limit, pair->serverBuffPos);
    memcpy(out, pair->serverBuff, toCopy);
    memmove(pair->serverBuff, &pair->serverBuff[toCopy],
            pair->serverBuffPos - toCopy);
    pair->serverBuffPos -= toCopy;

    return toCopy;
}

size_t unix_socket_accept_sendto(vfs_node_t fd, uint8_t *in, size_t limit,
                                 int flags, struct sockaddr_un *addr, uint32_t len)
{
    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    socket_handle_t *handle = fd->handle;
    unix_socket_pair_t *pair = handle->sock;
    if (limit > pair->clientBuffSize)
    {
        limit = pair->clientBuffSize;
    }

    while (true)
    {
        if (!pair->clientFds)
        {
            current_task->signal |= SIGMASK(SIGPIPE);
        }
        else if ((fd->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 (pair->clientBuffPos + limit) > pair->clientBuffSize)
        {
            return -(EWOULDBLOCK);
        }
        else if ((pair->clientBuffPos + limit) <= pair->clientBuffSize)
            break;
    }

    // spinlock already acquired
    memcpy(&pair->clientBuff[pair->clientBuffPos], in, limit);
    pair->clientBuffPos += limit;

    return limit;
}

int socket_accept_poll(vfs_node_t fd, int events)
{
    socket_handle_t *handle = fd->handle;
    unix_socket_pair_t *pair = handle->sock;
    int revents = 0;

    if (!pair->clientFds)
        revents |= EPOLLHUP;

    if (events & EPOLLOUT && pair->clientFds &&
        pair->clientBuffPos < pair->clientBuffSize)
        revents |= EPOLLOUT;

    if (events & EPOLLIN && pair->serverBuffPos > 0)
        revents |= EPOLLIN;

    return revents;
}

int socket_socket(int domain, int type, int protocol)
{
    // rest are not supported yet, only SOCK_STREAM
    if (!(type & 1))
    {
        return -(ENOSYS);
    }

    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_node_alloc(rootdir, buf);
    socknode->type = file_none;
    socknode->type = 0755;
    socknode->fsid = unix_socket_fsid;
    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    socket_t *unix_socket = malloc(sizeof(socket_t));
    memset(unix_socket, 0, sizeof(socket_t));

    socket_t *head = &first_unix_socket;
    while (head->next)
    {
        head = head->next;
    }

    head->next = unix_socket;

    handle->sock = unix_socket;
    handle->op = &socket_ops;
    socknode->handle = handle;

    unix_socket->timesOpened = 1;

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
        return -EBADF;
    }

    current_task->fds[i] = socknode;

    // if (type | SOCK_CLOEXEC)
    //     sockNode->closeOnExec = true;
    // if (type | SOCK_NONBLOCK)
    //   sockNode->flags |= O_NONBLOCK;

    return i;
}

int socket_bind(socket_t *sock, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sock->bindAddr)
        return -(EINVAL);

    // sanitize the filename
    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;

    // check if it already exists
    if (safe[0] != '@')
    {
        vfs_node_t new_node = vfs_open((const char *)safe);
        if (new_node)
        {
            vfs_close(new_node);
            free(safe);
            return -(EADDRINUSE);
        }
    }

    // make sure there are no duplicates
    size_t safeLen = strlen(safe);
    socket_t *browse = &first_unix_socket;
    while (browse)
    {
        if (browse->bindAddr && strlen(browse->bindAddr) == safeLen &&
            memcmp(safe, browse->bindAddr, safeLen) == 0)
            break;
        browse = browse->next;
    }

    // found a duplicate!
    if (browse)
    {
        free(safe);
        return -(EADDRINUSE);
    }

    sock->bindAddr = safe;
    return 0;
}

int socket_listen(socket_t *sock, int backlog)
{
    if (backlog == 0) // newer kernel behavior
        backlog = 1;
    if (backlog < 0)
        backlog = 128;

    // maybe do a typical array here
    sock->connMax = backlog;
    sock->backlog = calloc(sock->connMax * sizeof(unix_socket_pair_t *), 1);
    return 0;
}

int socket_accept(socket_t *sock, struct sockaddr_un *addr, socklen_t *addrlen)
{
    if (addr && addrlen && *addrlen > 0)
    {
    }

    while (true)
    {
        if (sock->connCurr > 0)
            break;
        // if (node->flags & O_NONBLOCK)
        // {
        //     sock->acceptWouldBlock = true;
        //     return -(EWOULDBLOCK);
        // }
        else
            sock->acceptWouldBlock = false;

        arch_enable_interrupt();
        arch_pause();
    }

    arch_disable_interrupt();

    // now pick the first thing! (sock spinlock already engaged)
    unix_socket_pair_t *pair = sock->backlog[0];
    pair->serverFds++;
    pair->established = true;
    pair->filename = strdup(sock->bindAddr);

    vfs_node_t acceptFd = unix_socket_accept_create(pair);
    sock->backlog[0] = 0; // just in case
    memmove(sock->backlog, &sock->backlog[1],
            (sock->connMax - 1) * sizeof(unix_socket_pair_t *));
    sock->connCurr--;

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
        return -EBADF;
    }

    current_task->fds[i] = acceptFd;

    return i;
}

int socket_connect(socket_t *sock, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sock->connMax != 0) // already ran listen()
        return -(ECONNREFUSED);

    if (sock->pair) // already ran connect()
        return -(EISCONN);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;
    size_t safeLen = strlen(safe);

    // find object
    socket_t *parent = &first_unix_socket;
    while (parent)
    {
        if (parent == sock)
        {
            parent = parent->next;
            continue;
        }

        if (parent->bindAddr && strlen(parent->bindAddr) == safeLen &&
            memcmp(safe, parent->bindAddr, safeLen) == 0)
            break;

        parent = parent->next;
    }
    free(safe); // no longer needed

    // todo: actual filesystem contact
    if (!parent)
        return -(ENOENT);

    // // nonblock edge case, check man page
    // if (parent->acceptWouldBlock && fd->flags & O_NONBLOCK)
    // {
    //     return -(EINPROGRESS); // use select, poll, or epoll
    // }

    // listen() hasn't yet ran
    if (!parent->connMax)
    {
        return -(ECONNREFUSED);
    }

    // todo!
    // spinlockAcquire(&parent->LOCK_SOCK);
    if (parent->connCurr >= parent->connMax)
    {
        return -(ECONNREFUSED); // no slot
    }
    unix_socket_pair_t *pair = unix_socket_allocate_pair();
    sock->pair = pair;
    pair->clientFds = 1;
    parent->backlog[parent->connCurr++] = pair;

    // todo!
    while (true)
    {
        if (pair->established)
            break;
        // wait for parent to accept this thing and have it's own fd on the side

        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

    return 0;
}

bool socket_close(void *fd)
{
    socket_t *unix_socket = fd;
    unix_socket->timesOpened--;
    if (unix_socket->pair)
    {
        unix_socket->pair->clientFds--;
        if (!unix_socket->pair->clientFds && !unix_socket->pair->serverFds)
            unix_socket_free_pair(unix_socket->pair);
    }
    if (unix_socket->timesOpened == 0)
    {
        socket_t *browse = &first_unix_socket;

        while (browse->next != unix_socket)
        {
            browse = browse->next;
        }

        browse->next = unix_socket->next;
        free(unix_socket);

        return true;
    }
    return true;
}

size_t unix_socket_recv_from(vfs_node_t fd, uint8_t *out, size_t limit, int flags,
                             struct sockaddr_un *addr, uint32_t *len)
{
    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    socket_t *socket = fd->handle;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);
    if (!pair->serverFds && pair->clientBuffPos == 0)
        return 0;
    while (true)
    {
        if (!pair->serverFds && pair->clientBuffPos == 0)
        {
            return 0;
        }
        else if ((fd->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 pair->clientBuffPos == 0)
        {
            return -(EWOULDBLOCK);
        }
        else if (pair->clientBuffPos > 0)
            break;
    }

    // spinlock already acquired
    size_t toCopy = MIN(limit, pair->clientBuffPos);
    memcpy(out, pair->clientBuff, toCopy);
    memmove(pair->clientBuff, &pair->clientBuff[toCopy],
            pair->clientBuffPos - toCopy);
    pair->clientBuffPos -= toCopy;

    return toCopy;
}

size_t unix_socket_send_to(vfs_node_t fd, uint8_t *in, size_t limit, int flags,
                           struct sockaddr_un *addr, uint32_t len)
{
    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    socket_t *socket = fd->handle;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);
    if (limit > pair->serverBuffSize)
    {
        limit = pair->serverBuffSize;
    }

    while (true)
    {
        if (!pair->serverFds)
        {
            current_task->signal |= SIGMASK(SIGPIPE);
            return -(EPIPE);
        }
        else if ((fd->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 (pair->serverBuffPos + limit) > pair->serverBuffSize)
        {
            return -(EWOULDBLOCK);
        }
        else if ((pair->serverBuffPos + limit) <= pair->serverBuffSize)
            break;
    }

    // spinlock already acquired
    memcpy(&pair->serverBuff[pair->serverBuffPos], in, limit);
    pair->serverBuffPos += limit;

    return limit;
}

size_t unix_socket_recv_msg(vfs_node_t fd, struct msghdr *msg, int flags)
{
    if (msg->msg_name || msg->msg_namelen > 0)
    {
        return -(ENOSYS);
    }
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;
    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr =
            (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));
        if (cnt > 0 && fs_callbacks[fd->fsid]->poll)
        {
            // check syscalls_fs.c for why this is necessary
            if (!(fs_callbacks[fd->fsid]->poll(fd, EPOLLIN) & EPOLLIN))
                return cnt;
        }
        size_t singleCnt = unix_socket_recv_from(fd, curr->iov_base, curr->len,
                                                 noblock ? MSG_DONTWAIT : 0, 0, 0);
        if (((int64_t)singleCnt) < 0)
            return singleCnt;

        cnt += singleCnt;
    }

    return cnt;
}

size_t unix_socket_accept_recv_msg(vfs_node_t fd, struct msghdr *msg,
                                   int flags)
{
    if (msg->msg_name || msg->msg_namelen > 0)
    {
        return -(ENOSYS);
    }
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;
    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr =
            (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));
        if (cnt > 0 && fs_callbacks[fd->fsid]->poll)
        {
            // check syscalls_fs.c for why this is necessary
            if (!(fs_callbacks[fd->fsid]->poll(fd, EPOLLIN) & EPOLLIN))
                return cnt;
        }
        size_t singleCnt = unix_socket_accept_recv_from(
            fd, curr->iov_base, curr->len, noblock ? MSG_DONTWAIT : 0, 0, 0);
        if ((int64_t)(singleCnt) < 0)
            return singleCnt;

        cnt += singleCnt;
    }

    return cnt;
}

int socket_poll(void *handle, int events)
{
    socket_t *socket = handle;
    int revents = 0;

    if (socket->connMax > 0)
    {
        // listen()
        if (socket->connCurr < socket->connMax) // can connect()
            revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
        if (socket->connCurr > 0) // can accept()
            revents |= (events & EPOLLIN) ? EPOLLIN : 0;
    }
    else if (socket->pair)
    {
        // connect()
        unix_socket_pair_t *pair = socket->pair;
        if (!pair->serverFds)
            revents |= EPOLLHUP;

        if (events & EPOLLOUT && pair->serverFds &&
            pair->serverBuffPos < pair->serverBuffSize)
            revents |= EPOLLOUT;

        if (events & EPOLLIN && pair->clientBuffPos > 0)
            revents |= EPOLLIN;
    }
    else
        revents |= EPOLLHUP;

    return revents;
}

int unix_socket_pair(int type, int protocol, int *sv)
{
    size_t sock1 = socket_socket(1, type, protocol);
    if ((int64_t)(sock1) < 0)
        return sock1;

    vfs_node_t sock1Fd = current_task->fds[sock1];

    unix_socket_pair_t *pair = unix_socket_allocate_pair();
    pair->clientFds = 1;
    pair->serverFds = 1;

    socket_t *sock = sock1Fd->handle;
    sock->pair = pair;

    vfs_node_t sock2Fd = unix_socket_accept_create(pair);

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
        return -EBADF;
    }

    current_task->fds[i] = sock2Fd;

    // finish it off
    sv[0] = sock1;
    sv[1] = i;

    return 0;
}

int socket_socket_poll(void *fd, int events)
{
    socket_t *socket = fd;
    int revents = 0;

    if (socket->connMax > 0)
    {
        // listen()
        if (socket->connCurr < socket->connMax) // can connect()
            revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
        if (socket->connCurr > 0) // can accept()
            revents |= (events & EPOLLIN) ? EPOLLIN : 0;
    }
    else if (socket->pair)
    {
        // connect()
        unix_socket_pair_t *pair = socket->pair;
        if (!pair->serverFds)
            revents |= EPOLLHUP;

        if (events & EPOLLOUT && pair->serverFds &&
            pair->serverBuffPos < pair->serverBuffSize)
            revents |= EPOLLOUT;

        if (events & EPOLLIN && pair->clientBuffPos > 0)
            revents |= EPOLLIN;
    }
    else
        revents |= EPOLLHUP;

    return revents;
}

size_t unix_socket_setsockopt(socket_t *sock, int level, int optname, const void *optval, socklen_t optlen)
{
    if (level != SOL_SOCKET)
    {
        return -ENOPROTOOPT;
    }

    switch (optname)
    {
    case SO_REUSEADDR:
        if (optlen < sizeof(int))
        {
            return -EINVAL;
        }
        sock->options.reuseaddr = *(int *)optval;
        break;
    case SO_KEEPALIVE:
        if (optlen < sizeof(int))
        {
            return -EINVAL;
        }
        sock->options.keepalive = *(int *)optval;
        break;
    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
        {
            return -EINVAL;
        }
        memcpy(&sock->options.sndtimeo, optval, sizeof(struct timeval));
        break;
    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
        {
            return -EINVAL;
        }
        memcpy(&sock->options.rcvtimeo, optval, sizeof(struct timeval));
        break;
    case SO_BINDTODEVICE:
        if (optlen > IFNAMSIZ)
        {
            return -EINVAL;
        }
        strncpy(sock->options.bind_to_dev, optval, optlen);
        sock->options.bind_to_dev[IFNAMSIZ - 1] = '\0';
        break;
    case SO_LINGER:
        if (optlen < sizeof(struct linger))
        {
            return -EINVAL;
        }
        memcpy(&sock->options.linger_opt, optval, sizeof(struct linger));
        break;
    case SO_SNDBUF:
        if (optlen < sizeof(int))
        {
            return -EINVAL;
        }
        sock->pair->serverBuffSize = *(int *)optval;
        if (sock->pair->serverBuffSize < BUFFER_SIZE)
        {
            sock->pair->serverBuffSize = BUFFER_SIZE;
        }
        break;
    case SO_RCVBUF:
        if (optlen < sizeof(int))
        {
            return -EINVAL;
        }
        sock->pair->clientBuffSize = *(int *)optval;
        if (sock->pair->clientBuffSize < BUFFER_SIZE)
        {
            sock->pair->clientBuffSize = BUFFER_SIZE;
        }
        break;
    case SO_PASSCRED:
        if (optlen < sizeof(int))
        {
            return -EINVAL;
        }
        sock->options.passcred = *(int *)optval;
        break;
    case SO_ATTACH_FILTER:
    {
        struct sock_fprog fprog;
        if (optlen < sizeof(fprog))
        {
            return -EINVAL;
        }
        memcpy(&fprog, optval, sizeof(fprog));
        if (fprog.len > 64 || fprog.len == 0)
        {
            return -EINVAL;
        }

        // 分配内存保存过滤器
        sock->options.filter = malloc(sizeof(struct sock_filter) * fprog.len);
        memcpy(sock->options.filter, fprog.filter, sizeof(struct sock_filter) * fprog.len);
        sock->options.filter_len = fprog.len;
        break;
    }
    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t unix_socket_getsockopt(socket_t *sock, int level, int optname, const void *optval, socklen_t *optlen)
{
    if (level != SOL_SOCKET)
    {
        return -ENOPROTOOPT;
    }

    // 获取选项值
    switch (optname)
    {
    case SO_REUSEADDR:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->options.reuseaddr;
        *optlen = sizeof(int);
        break;
    case SO_KEEPALIVE:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->options.keepalive;
        *optlen = sizeof(int);
        break;
    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
        {
            return -EINVAL;
        }
        memcpy(optval, &sock->options.sndtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;
    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
        {
            return -EINVAL;
        }
        memcpy(optval, &sock->options.rcvtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;
    case SO_BINDTODEVICE:
        if (*optlen < IFNAMSIZ)
        {
            return -EINVAL;
        }
        strncpy(optval, sock->options.bind_to_dev, IFNAMSIZ);
        *optlen = strlen(sock->options.bind_to_dev);
        break;
    case SO_PROTOCOL:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->protocol;
        *optlen = sizeof(int);
        break;
    case SO_LINGER:
        if (*optlen < sizeof(struct linger))
        {
            return -EINVAL;
        }
        memcpy(optval, &sock->options.linger_opt, sizeof(struct linger));
        *optlen = sizeof(struct linger);
        break;
    case SO_SNDBUF:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->pair->serverBuffSize;
        *optlen = sizeof(int);
        break;
    case SO_RCVBUF:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->pair->clientBuffSize;
        *optlen = sizeof(int);
        break;
    case SO_PASSCRED:
        if (*optlen < sizeof(int))
        {
            return -EINVAL;
        }
        *(int *)optval = sock->options.passcred;
        *optlen = sizeof(int);
        break;
    case SO_ATTACH_FILTER:
        if (*optlen < sizeof(struct sock_fprog))
        {
            return -EINVAL;
        }
        struct sock_fprog fprog = {
            .len = sock->options.filter_len,
            .filter = sock->options.filter};
        memcpy(optval, &fprog, sizeof(fprog));
        *optlen = sizeof(fprog);
        break;
    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

static int dummy()
{
    return -ENOSYS;
}

size_t unix_socket_getpeername(socket_t *socket, struct sockaddr_un *addr, socklen_t *len)
{
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);

    size_t actualLen = sizeof(addr->sun_family) + strlen(pair->filename);
    int toCopy = MIN(*len, actualLen);
    if (toCopy < sizeof(addr->sun_family))
        return -(EINVAL);
    addr->sun_family = 1;
    memcpy(addr->sun_path, pair->filename, toCopy - sizeof(addr->sun_family));
    *len = toCopy;
    return 0;
}

socket_op_t socket_ops = {
    .accept = socket_accept,
    .listen = socket_listen,
    .bind = socket_bind,
    .connect = socket_connect,
    .sendto = unix_socket_send_to,
    .recvfrom = unix_socket_recv_from,
    .recvmsg = unix_socket_recv_msg,
    .getpeername = unix_socket_getpeername,
};

socket_op_t accept_ops = {
    .connect = socket_connect,
    .sendto = unix_socket_accept_sendto,
    .recvfrom = unix_socket_accept_recv_from,
    .recvmsg = unix_socket_accept_recv_msg,
    .getpeername = unix_socket_getpeername,
};

static struct vfs_callback socket_callback =
    {
        .mount = (vfs_mount_t)dummy,
        .unmount = (vfs_unmount_t)dummy,
        .open = (vfs_open_t)dummy,
        .close = (vfs_close_t)socket_socket_close,
        .read = (vfs_read_t)dummy,
        .write = (vfs_write_t)dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .delete = (vfs_del_t)dummy,
        .rename = (vfs_rename_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
        .poll = (vfs_poll_t)socket_socket_poll,
};

static struct vfs_callback accept_callback =
    {
        .mount = (vfs_mount_t)dummy,
        .unmount = (vfs_unmount_t)dummy,
        .open = (vfs_open_t)dummy,
        .close = (vfs_close_t)socket_accept_close,
        .read = (vfs_read_t)dummy,
        .write = (vfs_write_t)dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .delete = (vfs_del_t)dummy,
        .rename = (vfs_rename_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
        .poll = (vfs_poll_t)socket_accept_poll,
};

void socketfs_init()
{
    memset(sockets, 0, sizeof(sockets));
    unix_socket_fsid = vfs_regist("socketfs", &socket_callback);
    unix_accept_fsid = vfs_regist("socketfs", &accept_callback);
    sockfs_root = vfs_node_alloc(rootdir, "sock");
    sockfs_root->type = file_dir;
    sockfs_root->mode = 0644;
}
