#include <net/socket.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>

// 互斥锁模拟（实际裸机环境需要原子操作实现）
typedef volatile int spinlock_t;
#define SPIN_LOCK(l) while (__sync_lock_test_and_set(&(l), 1))
#define SPIN_UNLOCK(l) __sync_lock_release(&(l))

socket_t sockets[MAX_SOCKETS] = {0};

static spinlock_t socket_lock = 0;

static vfs_node_t socketfs_root = NULL;
static int socketfs_id = 0;
static int sockfd_id = 0;

int sys_socket(int domain, int type, int protocol)
{
    SPIN_LOCK(socket_lock);

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
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    int sock_id = -1;
    for (int j = 0; j < MAX_PIPES; j++)
    {
        if (sockets[j].state == SOCKET_TYPE_UNUSED)
        {
            sock_id = j;
            break;
        }
    }

    char buf[256];
    sprintf(buf, "sock%d", sockfd_id++);
    vfs_node_t node = vfs_node_alloc(socketfs_root, strdup(buf));
    node->type = file_socket;
    node->handle = &sockets[sock_id];
    memset(&sockets[sock_id], 0, sizeof(socket_t));
    socket_t *socket = (socket_t *)node->handle;
    socket->type = type;
    socket->protocol = protocol;
    strcpy(socket->name, buf);
    socket->buf_head = 0;
    socket->buf_tail = 0;
    socket->sndbuf_size = BUFFER_SIZE;
    socket->rcvbuf_size = BUFFER_SIZE;
    socket->state = SOCKET_TYPE_UNCONNECTED;
    socket->fd = i;
    memset(&socket->options, 0, sizeof(socket->options));

    current_task->fds[i] = node;

    SPIN_UNLOCK(socket_lock);
    return i;
}

int sys_socketpair(int family, int type, int protocol, int *sv)
{
    // 创建第一个socket
    int fd1 = sys_socket(family, type, protocol);
    if (fd1 < 0)
    {
        return fd1;
    }

    // 创建第二个socket
    int fd2 = sys_socket(family, type, protocol);
    if (fd2 < 0)
    {
        sys_close(fd1);
        return fd2;
    }

    SPIN_LOCK(socket_lock);

    // 获取两个socket结构
    vfs_node_t sock1_node = current_task->fds[fd1];
    vfs_node_t sock2_node = current_task->fds[fd2];
    socket_t *sock1 = sock1_node->handle;
    socket_t *sock2 = sock2_node->handle;

    // 修正：需要找到实际的socket数组索引
    int sock1_idx = sock1 - sockets;
    int sock2_idx = sock2 - sockets;

    char buf[128];

    // 建立双向连接
    sock1->state = SOCKET_TYPE_CONNECTED;
    sock1->peer_fd = sock2_idx; // 使用数组索引而非文件描述符
    sprintf(buf, "sock%d", sockfd_id++);
    strcpy(sock1->name, buf);

    sock2->state = SOCKET_TYPE_CONNECTED;
    sock2->peer_fd = sock1_idx; // 使用数组索引而非文件描述符
    sprintf(buf, "sock%d", sockfd_id++);
    strcpy(sock2->name, buf);

    // 设置返回的fd对
    sv[0] = fd1;
    sv[1] = fd2;

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验
    if (sockfd < 0 || sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    vfs_node_t node = current_task->fds[sockfd];
    socket_t *sock = node->handle;

    if (!sock || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    // 准备sockaddr_un结构
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    size_t max_len = *addrlen - offsetof(struct sockaddr_un, sun_path);

    un->sun_family = 1;
    strncpy(un->sun_path, sock->name, max_len);
    un->sun_path[max_len - 1] = '\0';

    // 设置实际长度
    *addrlen = strlen(un->sun_path) + sizeof(un->sun_family);

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    // 复制socket名称
    const struct sockaddr_un *un = (struct sockaddr_un *)addr;

    const char *name = un->sun_path;
    for (; *name == '\0'; name++)
    {
    }

    if (strlen(name) >= SOCKET_NAME_LEN)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENAMETOOLONG; // 路径过长
    }

    strncpy(sock->name, name, SOCKET_NAME_LEN - 1);
    sock->name[SOCKET_NAME_LEN - 1] = '\0';

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_listen(int sockfd, int backlog)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    sock->state = SOCKET_TYPE_LISTENING;
    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *listen_sock = node->handle;

    if (!listen_sock || listen_sock->state != SOCKET_TYPE_LISTENING)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    // 查找连接请求并创建新socket
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
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    int sock_id = -1;
    for (int j = 0; j < MAX_PIPES; j++)
    {
        if (sockets[j].state == SOCKET_TYPE_UNUSED)
        {
            sock_id = j;
            break;
        }
    }

    char buf[256];
    sprintf(buf, "sock%d", i);
    vfs_node_t new_node = vfs_node_alloc(socketfs_root, strdup(buf));
    new_node->type = file_socket;
    new_node->handle = &sockets[sock_id];
    memset(&sockets[sock_id], 0, sizeof(socket_t));
    socket_t *socket = (socket_t *)new_node->handle;
    strcpy(socket->name, buf);
    socket->buf_head = 0;
    socket->buf_tail = 0;
    socket->state = SOCKET_TYPE_UNCONNECTED;
    socket->fd = i;

    current_task->fds[i] = new_node;

    SPIN_UNLOCK(socket_lock);
    return i;
}

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    if (sock->state != SOCKET_TYPE_UNCONNECTED && sock->state != SOCKET_TYPE_LISTENING)
    {
        SPIN_UNLOCK(socket_lock);
        return -EISCONN;
    }

    // 查找目标socket
    const struct sockaddr_un *un = (struct sockaddr_un *)addr;

    const char *name = un->sun_path;
    for (; *name == '\0'; name++)
    {
    }

    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].state == SOCKET_TYPE_LISTENING &&
            strcmp(sockets[i].name, name) == 0)
        {
            sock->peer_addr = malloc(sizeof(struct sockaddr));
            memcpy(sock->peer_addr, addr, addrlen);
            sock->peer_addrlen = addrlen;

            sock->state = SOCKET_TYPE_CONNECTED;
            sock->peer_fd = sockets[i].fd;
            strcpy(sock->name, name);

            SPIN_UNLOCK(socket_lock);
            return 0;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -ECONNREFUSED;
}

int64_t sys_send(int sockfd, const void *buf, size_t len, int flags)
{
    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    socket_t *peer = &sockets[sock->peer_fd];

    if (!peer)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    // 简化实现：直接拷贝数据到对方缓冲区
    size_t to_copy = len;
    if (to_copy > BUFFER_SIZE - peer->buf_tail)
    {
        to_copy = BUFFER_SIZE - peer->buf_tail;
    }

    memcpy(&peer->buffer[peer->buf_tail], buf, to_copy);
    peer->buf_tail = (peer->buf_tail + to_copy) % BUFFER_SIZE;

    SPIN_UNLOCK(socket_lock);
    return to_copy;
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    size_t available = (sock->buf_tail - sock->buf_head + BUFFER_SIZE) % BUFFER_SIZE;
    size_t to_copy = available > len ? len : available;

    if (to_copy > 0)
    {
        memcpy(buf, &sock->buffer[sock->buf_head], to_copy);
        sock->buf_head = (sock->buf_head + to_copy) % BUFFER_SIZE;
    }

    SPIN_UNLOCK(socket_lock);
    return to_copy;
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;
    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    if (msg->msg_controllen > 0)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    socket_t *peer = &sockets[sock->peer_fd];
    if (!peer || peer->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    size_t total_sent = 0;
    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *iov = &msg->msg_iov[i];
        if (!iov->iov_base || iov->len == 0)
            continue;

        size_t to_copy = iov->len;
        if (to_copy > BUFFER_SIZE - peer->buf_tail)
        {
            to_copy = BUFFER_SIZE - peer->buf_tail;
        }

        memcpy(&peer->buffer[peer->buf_tail], iov->iov_base, to_copy);
        peer->buf_tail = (peer->buf_tail + to_copy) % BUFFER_SIZE;
        total_sent += to_copy;
    }

    SPIN_UNLOCK(socket_lock);
    return total_sent;
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    socket_t *sock = node->handle;
    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    size_t total_recv = 0;
    size_t available = (sock->buf_tail - sock->buf_head + BUFFER_SIZE) % BUFFER_SIZE;

    for (int i = 0; i < msg->msg_iovlen && available > 0; i++)
    {
        struct iovec *iov = &msg->msg_iov[i];
        if (!iov->iov_base || iov->len == 0)
            continue;

        size_t to_copy = MIN(available, iov->len);
        memcpy(iov->iov_base, &sock->buffer[sock->buf_head], to_copy);

        sock->buf_head = (sock->buf_head + to_copy) % BUFFER_SIZE;
        available -= to_copy;
        total_recv += to_copy;
    }

    SPIN_UNLOCK(socket_lock);
    return total_recv;
}

int sys_socket_close(void *current)
{
    socket_t *socket = current;
    socket->state = SOCKET_TYPE_UNUSED;
    return 0;
}

int sys_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验
    if (sockfd < 0 || sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    vfs_node_t node = current_task->fds[sockfd];
    socket_t *sock = node->handle;
    if (!sock || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    // 仅支持SOL_SOCKET级别选项
    if (level != SOL_SOCKET)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOPROTOOPT;
    }

    // 处理不同选项
    switch (optname)
    {
    case SO_REUSEADDR:
        if (optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        sock->options.reuseaddr = *(int *)optval;
        break;
    case SO_KEEPALIVE:
        if (optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        sock->options.keepalive = *(int *)optval;
        break;
    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(&sock->options.sndtimeo, optval, sizeof(struct timeval));
        break;
    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(&sock->options.rcvtimeo, optval, sizeof(struct timeval));
        break;
    case SO_BINDTODEVICE:
        if (optlen > IFNAMSIZ)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        strncpy(sock->options.bind_to_dev, optval, optlen);
        sock->options.bind_to_dev[IFNAMSIZ - 1] = '\0';
        break;
    case SO_LINGER:
        if (optlen < sizeof(struct linger))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(&sock->options.linger_opt, optval, sizeof(struct linger));
        break;
    case SO_SNDBUF:
        if (optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        sock->sndbuf_size = *(int *)optval;
        if (sock->sndbuf_size < BUFFER_SIZE)
        {
            sock->sndbuf_size = BUFFER_SIZE;
        }
        break;
    case SO_RCVBUF:
        if (optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        sock->rcvbuf_size = *(int *)optval;
        if (sock->rcvbuf_size < BUFFER_SIZE)
        {
            sock->rcvbuf_size = BUFFER_SIZE;
        }
        break;
    case SO_PASSCRED:
        if (optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        sock->options.passcred = *(int *)optval;
        break;
    case SO_ATTACH_FILTER:
    {
        struct sock_fprog fprog;
        if (optlen < sizeof(fprog))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(&fprog, optval, sizeof(fprog));
        if (fprog.len > 64 || fprog.len == 0)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }

        // 分配内存保存过滤器
        sock->options.filter = malloc(sizeof(struct sock_filter) * fprog.len);
        memcpy(sock->options.filter, fprog.filter, sizeof(struct sock_filter) * fprog.len);
        sock->options.filter_len = fprog.len;
        break;
    }
    default:
        SPIN_UNLOCK(socket_lock);
        return -ENOPROTOOPT;
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验
    if (sockfd < 0 || sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    vfs_node_t node = current_task->fds[sockfd];
    socket_t *sock = node->handle;
    if (!sock || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    if (level != SOL_SOCKET)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOPROTOOPT;
    }

    // 获取选项值
    switch (optname)
    {
    case SO_REUSEADDR:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->options.reuseaddr;
        *optlen = sizeof(int);
        break;
    case SO_KEEPALIVE:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->options.keepalive;
        *optlen = sizeof(int);
        break;
    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(optval, &sock->options.sndtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;
    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(optval, &sock->options.rcvtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;
    case SO_BINDTODEVICE:
        if (*optlen < IFNAMSIZ)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        strncpy(optval, sock->options.bind_to_dev, IFNAMSIZ);
        *optlen = strlen(sock->options.bind_to_dev);
        break;
    case SO_PROTOCOL:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->protocol;
        *optlen = sizeof(int);
        break;
    case SO_LINGER:
        if (*optlen < sizeof(struct linger))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        memcpy(optval, &sock->options.linger_opt, sizeof(struct linger));
        *optlen = sizeof(struct linger);
        break;
    case SO_SNDBUF:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->sndbuf_size;
        *optlen = sizeof(int);
        break;
    case SO_RCVBUF:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->rcvbuf_size;
        *optlen = sizeof(int);
        break;
    case SO_PASSCRED:
        if (*optlen < sizeof(int))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        *(int *)optval = sock->options.passcred;
        *optlen = sizeof(int);
        break;
    case SO_ATTACH_FILTER:
        if (*optlen < sizeof(struct sock_fprog))
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        struct sock_fprog fprog = {
            .len = sock->options.filter_len,
            .filter = sock->options.filter};
        memcpy(optval, &fprog, sizeof(fprog));
        *optlen = sizeof(fprog);
        break;
    default:
        SPIN_UNLOCK(socket_lock);
        return -ENOPROTOOPT;
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}

uint64_t sys_shutdown(uint64_t sockfd, uint64_t how)
{
    if (sockfd < 0 || sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    vfs_node_t node = current_task->fds[sockfd];
    socket_t *sock = node->handle;

    if (!sock || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    // 验证how参数
    if (how < SHUT_RD || how > SHUT_RDWR)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    if (how == SHUT_RDWR)
    {
        sock->state = SOCKET_TYPE_UNCONNECTED;
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    // 验证文件描述符有效性
    if (fd < 0 || fd >= MAX_FD_NUM || current_task->fds[fd] == NULL)
    {
        return -EBADF;
    }

    vfs_node_t sock = current_task->fds[fd];

    // 验证是否为socket类型
    if (sock->type != file_socket)
    {
        return -ENOTSOCK;
    }

    // 从socket结构体中获取对端地址
    socket_t *s = sock->handle;
    if (!s->peer_addr)
    {
        return -ENOTCONN;
    }

    // 复制地址到用户空间
    socklen_t actual_len = MIN(*addrlen, s->peer_addrlen);
    memcpy(addr, s->peer_addr, actual_len);

    memcpy(addrlen, &actual_len, sizeof(socklen_t));

    return 0;
}

int socket_poll(void *file, size_t events)
{
    socket_t *socket = file;
    int revents = 0;

    // if (socket->max > 0)
    // {
    //     // listen()
    //     spinlockAcquire(&socket->LOCK_SOCK);
    //     if (socket->connCurr < socket->connMax) // can connect()
    //         revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
    //     if (socket->connCurr > 0) // can accept()
    //         revents |= (events & EPOLLIN) ? EPOLLIN : 0;
    //     spinlockRelease(&socket->LOCK_SOCK);
    // }
    // else if (socket->pair)
    // {
    //     // connect()
    //     UnixSocketPair *pair = socket->pair;
    //     spinlockAcquire(&pair->LOCK_PAIR);
    //     if (!pair->serverFds)
    //         revents |= EPOLLHUP;

    //     if (events & EPOLLOUT && pair->serverFds &&
    //         pair->serverBuffPos < pair->serverBuffSize)
    //         revents |= EPOLLOUT;

    //     if (events & EPOLLIN && pair->clientBuffPos > 0)
    //         revents |= EPOLLIN;
    //     spinlockRelease(&pair->LOCK_PAIR);
    // }
    // else
    revents |= EPOLLHUP;

    return revents;
}

static int dummy()
{
    return -ENOSYS;
}

static struct vfs_callback callback =
    {
        .mount = (vfs_mount_t)dummy,
        .unmount = (vfs_unmount_t)dummy,
        .open = (vfs_open_t)dummy,
        .close = (vfs_close_t)sys_socket_close,
        .read = (vfs_read_t)dummy,
        .write = (vfs_write_t)dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
        .poll = (vfs_poll_t)socket_poll,
};

void socketfs_init()
{
    socketfs_id = vfs_regist("socketfs", &callback);
    socketfs_root = vfs_node_alloc(rootdir, "sock");
    socketfs_root->type = file_dir;
    vfs_node_t node = vfs_child_append(socketfs_root, "sock0", NULL);
    node->type = file_socket;
}
