#include <arch/arch.h>
#include <net/net_syscall.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

bool socket_op_lock = false;

extern socket_op_t socket_ops;
extern socket_op_t accept_ops;

vfs_node_t sockfs_root = NULL;

int sockfsfd_id = 0;

socket_t first_unix_socket;

socket_t sockets[MAX_SOCKETS];

int unix_socket_fsid = 0;
int unix_accept_fsid = 0;

char *unix_socket_addr_safe(const struct sockaddr_un *addr, size_t len)
{
    size_t addrLen = len - sizeof(addr->sun_family);
    if (addrLen <= 0)
        return (void *)-(EINVAL);

    bool abstract = (addr->sun_path[0] == '\0');
    int skip = abstract ? 1 : 0;

    char *safe = calloc(addrLen + 2, 1);
    if (!safe)
        return (void *)-(ENOMEM);

    if (abstract && addr->sun_path[1] == '\0')
    {
        free(safe);
        return (char *)-EINVAL;
    }

    if (abstract)
    {
        safe[0] = ':';
        memcpy(safe + 1, addr->sun_path + skip, addrLen - skip);
    }
    else
    {
        memcpy(safe, addr->sun_path, addrLen);
    }

    return safe;
}

vfs_node_t unix_socket_accept_create(unix_socket_pair_t *dir)
{
    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_child_append(sockfs_root, buf, NULL);
    socknode->refcount++;
    socknode->type = file_socket;
    socknode->mode = 0700;

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    handle->op = &accept_ops;
    handle->sock = dir;

    socknode->fsid = unix_accept_fsid;
    socknode->handle = handle;

    return socknode;
}

unix_socket_pair_t *unix_socket_allocate_pair()
{
    unix_socket_pair_t *pair = calloc(sizeof(unix_socket_pair_t), 1);
    pair->clientBuffSize = BUFFER_SIZE;
    pair->serverBuffSize = BUFFER_SIZE;
    pair->serverBuff = malloc(pair->serverBuffSize);
    pair->clientBuff = malloc(pair->clientBuffSize);
    pair->pending_fds = malloc(4 * sizeof(int));
    pair->pending_files = malloc(4 * sizeof(fd_t));
    pair->pending_fds_size = 4;
    pair->pending_fds_count = 0;
    return pair;
}

void unix_socket_free_pair(unix_socket_pair_t *pair)
{
    free(pair->clientBuff);
    free(pair->serverBuff);
    free(pair->filename);
    free(pair->pending_fds);
    free(pair->pending_files);
    free(pair);
}

bool socket_accept_close(socket_handle_t *handle)
{
    unix_socket_pair_t *pair = handle->sock;
    pair->serverFds--;

    if (pair->serverFds == 0 && pair->clientFds == 0)
        unix_socket_free_pair(pair);

    return false;
}

bool socket_socket_close(socket_handle_t *socket_handle)
{
    socket_t *unixSocket = socket_handle->sock;
    if (unixSocket->timesOpened >= 1)
    {
        unixSocket->timesOpened--;
    }
    if (unixSocket->pair)
    {
        unixSocket->pair->clientFds--;
        if (!unixSocket->pair->clientFds && !unixSocket->pair->serverFds)
            unix_socket_free_pair(unixSocket->pair);
    }
    if (unixSocket->timesOpened == 0)
    {
        socket_t *browse = &first_unix_socket;

        while (browse && browse->next != unixSocket)
        {
            browse = browse->next;
        }

        browse->next = unixSocket->next;
        free(unixSocket);
        free(socket_handle);

        return true;
    }

    return false;
}

size_t unix_socket_accept_recv_from(uint64_t fd, uint8_t *out, size_t limit,
                                    int flags, struct sockaddr_un *addr,
                                    uint32_t *len)
{
    (void)addr;
    (void)len;

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;
    if (!pair->clientFds && pair->serverBuffPos == 0)
        return 0;
    while (true)
    {
        if (!pair->clientFds && pair->serverBuffPos == 0)
        {
            return 0;
        }
        else if ((current_task->fds[fd]->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 pair->serverBuffPos == 0)
        {
            return -(EWOULDBLOCK);
        }
        else if (pair->serverBuffPos > 0)
            break;
    }

    while (socket_op_lock)
    {
        arch_pause();
    }
    socket_op_lock = true;

    // spinlock already acquired
    size_t toCopy = MIN(limit, pair->serverBuffPos);
    memcpy(out, pair->serverBuff, toCopy);
    memmove(pair->serverBuff, &pair->serverBuff[toCopy],
            pair->serverBuffPos - toCopy);
    pair->serverBuffPos -= toCopy;

    socket_op_lock = false;

    return toCopy;
}

size_t unix_socket_accept_sendto(uint64_t fd, uint8_t *in, size_t limit,
                                 int flags, struct sockaddr_un *addr, uint32_t len)
{
    while (socket_op_lock)
    {
        arch_pause();
    }
    socket_op_lock = true;

    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
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

        if ((pair->clientBuffPos + limit) <= pair->clientBuffSize)
            break;

        if (current_task->fds[fd]->flags & O_NONBLOCK || flags & MSG_DONTWAIT)
        {
            socket_op_lock = false;
            return -(EWOULDBLOCK);
        }

        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

    memcpy(&pair->clientBuff[pair->clientBuffPos], in, limit);
    pair->clientBuffPos += limit;

    socket_op_lock = false;

    return limit;
}

int socket_accept_poll(void *file, int events)
{
    socket_handle_t *handle = file;
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
    // if (!(type & 1))
    // {
    //     return -ENOSYS;
    // }

    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_node_alloc(sockfs_root, buf);
    socknode->type = file_socket;
    socknode->fsid = unix_socket_fsid;
    socknode->refcount++;
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

    current_task->fds[i] = malloc(sizeof(fd_t));
    current_task->fds[i]->node = socknode;
    current_task->fds[i]->offset = 0;
    current_task->fds[i]->flags = 0;

    // if (type | SOCK_CLOEXEC)
    //     sockNode->closeOnExec = true;
    // if (type | SOCK_NONBLOCK)
    //   sockNode->flags |= O_NONBLOCK;

    return i;
}

int socket_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->bindAddr)
        return -(EINVAL);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;

    bool is_abstract = (addr->sun_path[0] == '\0');

    if (!is_abstract)
    {
        vfs_node_t new_node = vfs_open(safe);
        if (new_node)
        {
            vfs_close(new_node);
            free(safe);
            return -(EADDRINUSE);
        }
    }

    size_t safeLen = strlen(safe);
    socket_t *browse = &first_unix_socket;
    while (browse)
    {
        if (browse != sock && browse->bindAddr &&
            strlen(browse->bindAddr) == safeLen &&
            memcmp(safe, browse->bindAddr, safeLen) == 0)
            break;
        browse = browse->next;
    }

    if (browse)
    {
        free(safe);
        return -(EADDRINUSE);
    }

    sock->bindAddr = safe;
    return 0;
}

int socket_listen(uint64_t fd, int backlog)
{
    if (backlog == 0) // newer kernel behavior
        backlog = 1;
    if (backlog < 0)
        backlog = 128;

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    // maybe do a typical array here
    sock->connMax = backlog;
    sock->backlog = calloc(sock->connMax * sizeof(unix_socket_pair_t *), 1);
    return 0;
}

int socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags)
{
    if (addr && addrlen && *addrlen > 0)
    {
    }

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    while (true)
    {
        if (sock->connCurr > 0)
            break;
        if (current_task->fds[fd]->flags & O_NONBLOCK)
        {
            sock->acceptWouldBlock = true;
            return -(EWOULDBLOCK);
        }
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

    current_task->fds[i] = malloc(sizeof(fd_t));
    current_task->fds[i]->node = acceptFd;
    current_task->fds[i]->offset = 0;
    current_task->fds[i]->flags = flags;

    return i;
}

int socket_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->connMax != 0) // already ran listen()
        return -(ECONNREFUSED);

    if (sock->pair) // already ran connect()
        return -(EISCONN);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;
    size_t safeLen = strlen(safe);

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
    free(safe);

    if (!parent)
        return -(ENOENT);

    if (!parent->connMax)
    {
        return -(ECONNREFUSED);
    }

    if (parent->connCurr >= parent->connMax)
    {
        return -(ECONNREFUSED); // no slot
    }

    unix_socket_pair_t *pair = unix_socket_allocate_pair();
    sock->pair = pair;
    parent->pair = pair;
    pair->clientFds = 1;
    parent->backlog[parent->connCurr++] = pair;

    while (!pair->established)
    {
        arch_enable_interrupt();

        arch_pause();
    }

    arch_disable_interrupt();

    sock->options.peercred.pid = current_task->pid;
    sock->options.peercred.uid = current_task->uid;
    sock->options.peercred.gid = current_task->gid;
    sock->options.has_peercred = true;

    return 0;
}

size_t unix_socket_recv_from(uint64_t fd, uint8_t *out, size_t limit, int flags,
                             struct sockaddr_un *addr, uint32_t *len)
{
    while (socket_op_lock)
    {
        arch_pause();
    }

    socket_op_lock = true;

    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *socket = handle->sock;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
    {
        socket_op_lock = false;
        return -(ENOTCONN);
    }
    if (!pair->serverFds && pair->clientBuffPos == 0)
        return 0;
    while (true)
    {
        if (!pair->serverFds && pair->clientBuffPos == 0)
        {
            socket_op_lock = false;
            return 0;
        }
        else if ((current_task->fds[fd]->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 pair->clientBuffPos == 0)
        {
            socket_op_lock = false;
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

    socket_op_lock = false;

    return toCopy;
}

size_t unix_socket_send_to(uint64_t fd, uint8_t *in, size_t limit, int flags,
                           struct sockaddr_un *addr, uint32_t len)
{
    // useless unless SOCK_DGRAM
    (void)addr;
    (void)len;

    while (socket_op_lock)
    {
        arch_pause();
    }

    socket_op_lock = true;

    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *socket = handle->sock;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
    {
        socket_op_lock = false;
        return -(ENOTCONN);
    }
    if (limit > pair->serverBuffSize)
    {
        limit = pair->serverBuffSize;
    }

    while (true)
    {
        if (!pair->serverFds)
        {
            current_task->signal |= SIGMASK(SIGPIPE);
            socket_op_lock = false;
            return -(EPIPE);
        }
        else if ((current_task->fds[fd]->flags & O_NONBLOCK || flags & MSG_DONTWAIT) &&
                 (pair->serverBuffPos + limit) > pair->serverBuffSize)
        {
            socket_op_lock = false;
            return -(EWOULDBLOCK);
        }
        else if ((pair->serverBuffPos + limit) <= pair->serverBuffSize)
            break;
    }

    // spinlock already acquired
    memcpy(&pair->serverBuff[pair->serverBuffPos], in, limit);
    pair->serverBuffPos += limit;

    socket_op_lock = false;

    return limit;
}

size_t unix_socket_recv_msg(uint64_t fd, struct msghdr *msg, int flags)
{
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    if (msg->msg_control)
    {
        socket_handle_t *handle = current_task->fds[fd]->node->handle;
        socket_t *socket = handle->sock;
        unix_socket_pair_t *pair = socket->pair;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        while (socket_op_lock)
            arch_pause();
        socket_op_lock = true;

        if (pair->pending_fds_count > 0)
        {
            size_t max_fds = (msg->msg_controllen - CMSG_LEN(0)) / sizeof(int);
            int num_fds = MIN(pair->pending_fds_count, max_fds);

            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(num_fds * sizeof(int));

            int *dest_fds = (int *)CMSG_DATA(cmsg);
            for (int i = 0; i < num_fds; i++)
            {
                int f = -1;
                for (f = 3; f < MAX_FD_NUM; f++)
                {
                    if (!current_task->fds[f])
                    {
                        break;
                    }
                }

                if (f == -1)
                {
                    socket_op_lock = false;
                    return -EMFILE;
                }

                dest_fds[i] = f;

                current_task->fds[dest_fds[i]] = malloc(sizeof(fd_t));
                memcpy(current_task->fds[dest_fds[i]], &pair->pending_files[i], sizeof(fd_t));
            }

            memmove(pair->pending_fds, &pair->pending_fds[num_fds],
                    (pair->pending_fds_count - num_fds) * sizeof(fd_t));
            pair->pending_fds_count -= num_fds;

            msg->msg_controllen = cmsg->cmsg_len;
        }
        else
        {
            msg->msg_controllen = 0;
        }

        socket_op_lock = false;
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));
        if (cnt > 0 && fs_callbacks[current_task->fds[fd]->node->fsid]->poll)
        {
            if (!(fs_callbacks[current_task->fds[fd]->node->fsid]->poll(current_task->fds[fd]->node, EPOLLIN) & EPOLLIN))
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

size_t unix_socket_send_msg(uint64_t fd, const struct msghdr *msg, int flags)
{
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    if (msg->msg_controllen > 0)
    {
        if (msg->msg_control == NULL ||
            msg->msg_controllen < sizeof(struct cmsghdr))
        {
            return -EINVAL;
        }
    }

    if (msg->msg_control)
    {
        socket_handle_t *handle = current_task->fds[fd]->node->handle;
        socket_t *socket = handle->sock;
        unix_socket_pair_t *pair = socket->pair;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
        for (; cmsg != NULL; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS)
            {

                int *fds = (int *)CMSG_DATA(cmsg);
                int num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                // 加锁保证原子操作
                while (socket_op_lock)
                    arch_pause();
                socket_op_lock = true;

                for (int i = 0; i < num_fds; i++)
                {
                    pair->pending_fds[pair->pending_fds_count] = fds[i];
                    memcpy(&pair->pending_files[pair->pending_fds_count++], current_task->fds[fds[i]], sizeof(fd_t));
                    current_task->fds[fds[i]]->node->refcount++;
                }

                socket_op_lock = false;
            }
        }
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));

        size_t singleCnt = unix_socket_send_to(
            fd, curr->iov_base, curr->len,
            noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0)
            return singleCnt;

        cnt += singleCnt;
    }
    return cnt;
}

size_t unix_socket_accept_recv_msg(uint64_t fd, struct msghdr *msg,
                                   int flags)
{
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    if (msg->msg_control)
    {
        socket_handle_t *handle = current_task->fds[fd]->node->handle;
        unix_socket_pair_t *pair = handle->sock;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        while (socket_op_lock)
            arch_pause();
        socket_op_lock = true;

        if (pair->pending_fds_count > 0)
        {
            size_t max_fds = (msg->msg_controllen - CMSG_LEN(0)) / sizeof(int);
            int num_fds = MIN(pair->pending_fds_count, max_fds);

            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(num_fds * sizeof(int));

            int *dest_fds = (int *)CMSG_DATA(cmsg);
            for (int i = 0; i < num_fds; i++)
            {
                int f = -1;
                for (f = 3; f < MAX_FD_NUM; f++)
                {
                    if (!current_task->fds[f])
                    {
                        break;
                    }
                }

                if (f == -1)
                {
                    socket_op_lock = false;
                    return -EMFILE;
                }

                dest_fds[i] = f;

                current_task->fds[dest_fds[i]] = malloc(sizeof(fd_t));
                memcpy(current_task->fds[dest_fds[i]], &pair->pending_files[i], sizeof(fd_t));
            }

            memmove(pair->pending_fds, &pair->pending_fds[num_fds],
                    (pair->pending_fds_count - num_fds) * sizeof(fd_t));
            pair->pending_fds_count -= num_fds;

            msg->msg_controllen = cmsg->cmsg_len;
        }
        else
        {
            msg->msg_controllen = 0;
        }

        socket_op_lock = false;
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr =
            (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));
        if (cnt > 0 && fs_callbacks[current_task->fds[fd]->node->fsid]->poll)
        {
            if (!(fs_callbacks[current_task->fds[fd]->node->fsid]->poll(current_task->fds[fd]->node, EPOLLIN) & EPOLLIN))
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

size_t unix_socket_accept_send_msg(uint64_t fd, const struct msghdr *msg, int flags)
{
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    if (msg->msg_controllen > 0)
    {
        if (msg->msg_control == NULL ||
            msg->msg_controllen < sizeof(struct cmsghdr))
        {
            return -EINVAL;
        }
    }

    if (msg->msg_control)
    {
        socket_handle_t *handle = current_task->fds[fd]->node->handle;
        unix_socket_pair_t *pair = handle->sock;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
        for (; cmsg != NULL; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS)
            {

                int *fds = (int *)CMSG_DATA(cmsg);
                int num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                // 加锁保证原子操作
                while (socket_op_lock)
                    arch_pause();
                socket_op_lock = true;

                for (int i = 0; i < num_fds; i++)
                {
                    pair->pending_fds[pair->pending_fds_count] = fds[i];
                    memcpy(&pair->pending_files[pair->pending_fds_count++], current_task->fds[fds[i]], sizeof(fd_t));
                    current_task->fds[fds[i]]->node->refcount++;
                }

                socket_op_lock = false;
            }
        }
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));

        size_t singleCnt = unix_socket_accept_sendto(
            fd, curr->iov_base, curr->len,
            noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0)
            return singleCnt;

        cnt += singleCnt;
    }
    return cnt;
}

int unix_socket_pair(int type, int protocol, int *sv)
{
    size_t sock1 = socket_socket(1, type, protocol);
    if ((int64_t)(sock1) < 0)
        return sock1;

    vfs_node_t sock1Fd = current_task->fds[sock1]->node;

    unix_socket_pair_t *pair = unix_socket_allocate_pair();
    pair->clientFds = 1;
    pair->serverFds = 1;

    socket_handle_t *handle = sock1Fd->handle;
    socket_t *sock = handle->sock;
    sock->pair = pair;
    handle->sock = sock;

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
        unix_socket_free_pair(pair);
        sys_close(sock1);
        vfs_free(sock2Fd);
        return -EBADF;
    }

    sock->options.peercred.pid = current_task->pid;
    sock->options.peercred.uid = current_task->uid;
    sock->options.peercred.gid = current_task->gid;
    sock->options.has_peercred = true;

    socket_handle_t *new_handle = sock2Fd->handle;
    unix_socket_pair_t *new_sock = new_handle->sock;

    sock->options.peercred = sock->options.peercred;
    sock->options.has_peercred = true;

    current_task->fds[i] = malloc(sizeof(fd_t));
    current_task->fds[i]->node = sock2Fd;
    current_task->fds[i]->offset = 0;
    current_task->fds[i]->flags = 0;

    // finish it off
    sv[0] = sock1;
    sv[1] = i;

    return 0;
}

int socket_socket_poll(void *file, int events)
{
    socket_handle_t *handler = file;
    socket_t *socket = handler->sock;
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

size_t unix_socket_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (level != SOL_SOCKET)
    {
        return -ENOPROTOOPT;
    }
    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

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

size_t unix_socket_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen)
{
    if (level != SOL_SOCKET)
    {
        return -ENOPROTOOPT;
    }
    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

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
    case SO_PEERCRED:
        if (!sock->options.has_peercred)
        {
            return -ENODATA;
        }
        if (*optlen < sizeof(struct ucred))
        {
            return -EINVAL;
        }
        memcpy(optval, &sock->options.peercred, sizeof(struct ucred));
        *optlen = sizeof(struct ucred);
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
    return 0;
}

size_t unix_socket_getpeername(uint64_t fd, struct sockaddr_un *addr, socklen_t *len)
{
    socket_handle_t *handle = current_task->fds[fd]->node->handle;
    socket_t *socket = handle->sock;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);

    size_t actualLen = sizeof(addr->sun_family) + strlen(pair->filename);
    int toCopy = MIN(*len, actualLen);
    if (toCopy < sizeof(addr->sun_family))
        return -(EINVAL);
    addr->sun_family = 1;
    if (pair->filename[0] == ':')
    {
        memcpy(addr->sun_path + 1, pair->filename + 1, toCopy - sizeof(addr->sun_family));
        addr->sun_path[0] = '\0';
    }
    else
    {
        memcpy(addr->sun_path, pair->filename, toCopy - sizeof(addr->sun_family));
    }
    *len = toCopy;
    return 0;
}

void socket_open(void *parent, const char *name, vfs_node_t node)
{
    // socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    // memset(handle, 0, sizeof(socket_handle_t));
    // if (node->fsid == unix_socket_fsid)
    // {
    //     uint64_t fd = malloc(sizeof(socket_t));
    //     memset(sock, 0, sizeof(socket_t));
    //     handle->sock = sock;
    //     sock->timesOpened++;
    //     node->handle = handle;
    //     handle->op = &accept_ops;
    // }
    // else
    // {
    //     unix_socket_pair_t *pair = malloc(sizeof(unix_socket_pair_t));
    //     memset(pair, 0, sizeof(socket_t));
    //     handle->sock = pair;
    //     pair->serverFds++;
    //     node->handle = handle;
    //     handle->op = &accept_ops;
    // }
}

int socket_stat(void *file, vfs_node_t node)
{
    return 0;
}

socket_op_t socket_ops = {
    .accept = socket_accept,
    .listen = socket_listen,
    .bind = socket_bind,
    .connect = socket_connect,
    .sendto = unix_socket_send_to,
    .recvfrom = unix_socket_recv_from,
    .sendmsg = unix_socket_send_msg,
    .recvmsg = unix_socket_recv_msg,
    .getpeername = unix_socket_getpeername,
    .getsockopt = unix_socket_getsockopt,
    .setsockopt = unix_socket_setsockopt,
};

socket_op_t accept_ops = {
    .sendto = unix_socket_accept_sendto,
    .recvfrom = unix_socket_accept_recv_from,
    .sendmsg = unix_socket_accept_send_msg,
    .recvmsg = unix_socket_accept_recv_msg,
    .getsockopt = unix_socket_getsockopt,
    .setsockopt = unix_socket_setsockopt,
};

static struct vfs_callback socket_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)socket_open,
    .close = (vfs_close_t)socket_socket_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)socket_socket_poll,
    .resize = (vfs_resize_t)dummy,
};

static struct vfs_callback accept_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)socket_open,
    .close = (vfs_close_t)socket_accept_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)socket_accept_poll,
    .resize = (vfs_resize_t)dummy,
};

void socketfs_init()
{
    memset(sockets, 0, sizeof(sockets));
    unix_socket_fsid = vfs_regist("socketfs", &socket_callback);
    unix_accept_fsid = vfs_regist("socketfs", &accept_callback);
    sockfs_root = vfs_node_alloc(rootdir, "sock");
    sockfs_root->type = file_dir;
    sockfs_root->mode = 0644;
    memset(&first_unix_socket, 0, sizeof(socket_handle_t));
}
