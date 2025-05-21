#include <arch/arch.h>
#include <net/net_syscall.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

// 互斥锁模拟（实际裸机环境需要原子操作实现）
typedef volatile int spinlock_t;
#define SPIN_LOCK(l) while (__sync_lock_test_and_set(&(l), 1))
#define SPIN_UNLOCK(l) __sync_lock_release(&(l))

socket_t sockets[MAX_SOCKETS] = {0};

static spinlock_t socket_lock = 0;

static vfs_node_t socketfs_root = NULL;
static int socketfs_id = 0;
static int sockfd_id = 0;

// 创建新连接
static int create_new_connection(socket_t *server)
{
    SPIN_LOCK(socket_lock);

    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (server->inners[i] == NULL)
        {
            server->inners[i] = malloc(sizeof(socket_inner_t));
            memset(server->inners[i], 0, sizeof(socket_inner_t));
            server->inners[i]->is_active = false;
            server->inners[i]->peer_closed = false;
            server->conn_count++;
            SPIN_UNLOCK(socket_lock);
            return i;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -ENOMEM;
}

// 销毁连接
static void destroy_connection(socket_t *sock, int conn_idx)
{
    SPIN_LOCK(socket_lock);

    if (sock->inners[conn_idx])
    {
        free(sock->inners[conn_idx]);
        sock->inners[conn_idx] = NULL;
        sock->conn_count--;
    }

    SPIN_UNLOCK(socket_lock);
}

int socket_socket(int domain, int type, int protocol)
{
    SPIN_LOCK(socket_lock);

    // 查找空闲文件描述符
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            fd = i;
            break;
        }
    }
    if (fd == -1)
    {
        SPIN_UNLOCK(socket_lock);
        return -EMFILE;
    }

    // 查找空闲socket结构
    int sock_id = -1;
    for (int j = 0; j < MAX_SOCKETS; j++)
    {
        if (sockets[j].state == SOCKET_TYPE_UNUSED)
        {
            sock_id = j;
            break;
        }
    }
    if (sock_id == -1)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENFILE;
    }

    // 初始化socket结构
    memset(&sockets[sock_id], 0, sizeof(socket_t));
    socket_t *socket = &sockets[sock_id];
    socket->domain = domain;
    socket->type = type;
    socket->protocol = protocol;
    socket->state = SOCKET_TYPE_UNCONNECTED;
    socket->sndbuf_size = BUFFER_SIZE;
    socket->rcvbuf_size = BUFFER_SIZE;
    socket->ref_count = 1;

    // 创建VFS节点
    char name[16];
    sprintf(name, "sock%d", sockfd_id++);
    vfs_node_t node = vfs_node_alloc(socketfs_root, name);
    node->type = file_socket;
    node->handle = socket;
    node->mode = 0755;
    node->fsid = socketfs_id;

    current_task->fds[fd] = node;
    SPIN_UNLOCK(socket_lock);
    return fd;
}

int socket_socketpair(int family, int type, int protocol, int *sv)
{
    // 创建两个socket
    int fd1 = socket_socket(family, type, protocol);
    if (fd1 < 0)
        return fd1;

    int fd2 = socket_socket(family, type, protocol);
    if (fd2 < 0)
    {
        sys_close(fd1);
        return fd2;
    }

    SPIN_LOCK(socket_lock);

    vfs_node_t sock1_node = current_task->fds[fd1];
    vfs_node_t sock2_node = current_task->fds[fd2];
    socket_t *sock1 = sock1_node->handle;
    socket_t *sock2 = sock2_node->handle;

    SPIN_UNLOCK(socket_lock);
    // 为每个socket创建两个方向的连接
    int conn1 = create_new_connection(sock1);
    int conn2 = create_new_connection(sock2);
    SPIN_LOCK(socket_lock);

    // 设置连接元数据
    sock1->inners[conn1]->peer_fd = sock2 - sockets;
    sock1->inners[conn1]->is_active = true;
    sock2->inners[conn2]->peer_fd = sock1 - sockets;
    sock2->inners[conn2]->is_active = true;

    // 设置状态
    sock1->state = sock2->state = SOCKET_TYPE_CONNECTED;

    sv[0] = fd1;
    sv[1] = fd2;

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
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

    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    socklen_t len = MIN(*addrlen, sizeof(sock->name) + sizeof(un->sun_family));

    un->sun_family = sock->domain;
    memcpy(un->sun_path, sock->name, len - sizeof(un->sun_family));
    *addrlen = sizeof(struct sockaddr_un);

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验增强
    if (addrlen < sizeof(sa_family_t))
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

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

    const struct sockaddr_un *un = (struct sockaddr_un *)addr;
    int is_abstract = (un->sun_path[0] == '\0');

    if (is_abstract)
    {
        size_t name_len = addrlen - offsetof(struct sockaddr_un, sun_path);
        if (name_len == 0)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        if (strnlen(un->sun_path + 1, name_len - 1) == 0)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        if (strnlen(addr->sun_path + 1, name_len) == 0)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        if (name_len > sizeof(un->sun_path))
        {
            SPIN_UNLOCK(socket_lock);
            return -ENAMETOOLONG;
        }
        memcpy(sock->name, un->sun_path + 1, name_len);
        memset(&sock->name[name_len], 0, sizeof(sock->name) - name_len);
    }
    else
    {
        const char *name = un->sun_path;
        while (*name == '\0' && name < un->sun_path + sizeof(un->sun_path))
        {
            name++;
        }
        size_t path_len = strlen(name);

        if (path_len == 0)
        {
            SPIN_UNLOCK(socket_lock);
            return -EINVAL;
        }
        if (path_len >= sizeof(un->sun_path))
        {
            SPIN_UNLOCK(socket_lock);
            return -ENAMETOOLONG;
        }
        strncpy(sock->name, name, sizeof(sock->name) - 1);
        sock->name[sizeof(sock->name) - 1] = '\0';

        vfs_mkfile(name);
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_listen(int sockfd, int backlog)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    // 初始化等待连接队列
    sock->pending_conns = malloc(sizeof(int) * backlog);
    sock->max_pending = backlog;
    sock->conn_count = 0;
    sock->state = SOCKET_TYPE_LISTENING;

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *listen_sock = node->handle;
    if (listen_sock->state != SOCKET_TYPE_LISTENING)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    // 等待新连接
    while (listen_sock->conn_count == 0)
    {
        SPIN_UNLOCK(socket_lock);
        arch_pause();
        SPIN_LOCK(socket_lock);
    }

    // 获取第一个等待连接
    int client_idx = listen_sock->pending_conns[0];
    memmove(&listen_sock->pending_conns[0],
            &listen_sock->pending_conns[1],
            sizeof(int) * (listen_sock->conn_count - 1));
    listen_sock->conn_count--;

    // 创建新socket
    int new_fd = socket_socket(listen_sock->domain, listen_sock->type, listen_sock->protocol);
    if (new_fd < 0)
    {
        SPIN_UNLOCK(socket_lock);
        return new_fd;
    }

    vfs_node_t new_node = current_task->fds[new_fd];
    socket_t *client_sock = new_node->handle;

    // 建立连接关系
    int conn_idx = create_new_connection(client_sock);
    client_sock->inners[conn_idx]->is_active = true;
    client_sock->inners[conn_idx]->peer_fd = client_idx;
    client_sock->state = SOCKET_TYPE_CONNECTED;

    // 设置对端socket的连接
    socket_t *peer = &sockets[client_idx];
    int peer_conn = create_new_connection(peer);
    peer->inners[peer_conn]->is_active = true;
    peer->inners[peer_conn]->peer_fd = client_sock - sockets;

    SPIN_UNLOCK(socket_lock);
    return new_fd;
}

int socket_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验增强
    if (addrlen < sizeof(sa_family_t))
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return sock->state == SOCKET_TYPE_CONNECTED ? -EISCONN : -EINVAL;
    }

    const struct sockaddr_un *un = (struct sockaddr_un *)addr;
    size_t path_len = 0;
    bool is_abstract = (un->sun_path[0] == '\0');

    // 计算路径长度
    if (is_abstract)
    {
        path_len = addrlen - offsetof(struct sockaddr_un, sun_path);
    }
    else
    {
        const char *p = un->sun_path;
        while (p - un->sun_path < sizeof(un->sun_path) && *p)
            p++;
        path_len = p - un->sun_path;
    }

    // 查找匹配的监听socket
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].state == SOCKET_TYPE_LISTENING &&
            ((memcmp(sockets[i].name, is_abstract ? (un->sun_path + 1) : un->sun_path, path_len) == 0) || vfs_open(is_abstract ? (un->sun_path + 1) : un->sun_path)))
        {
            // 检查等待队列是否已满
            if (sockets[i].conn_count >= sockets[i].max_pending)
            {
                SPIN_UNLOCK(socket_lock);
                return -ECONNREFUSED;
            }

            // 创建新连接
            int conn_idx = create_new_connection(&sockets[i]);
            if (conn_idx < 0)
            {
                SPIN_UNLOCK(socket_lock);
                return -ENOMEM;
            }

            // 设置连接元数据
            sockets[i].inners[conn_idx]->peer_fd = sock - sockets;
            sockets[i].inners[conn_idx]->is_active = true;
            sockets[i].pending_conns[sockets[i].conn_count++] = sock - sockets;

            // 设置当前socket状态
            sock->state = SOCKET_TYPE_CONNECTED;
            SPIN_UNLOCK(socket_lock);
            return 0;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -ECONNREFUSED;
}
int64_t socket_send(int sockfd, const void *buf, size_t len, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    int64_t total_sent = 0;
    const uint8_t *src = buf;

    // 遍历所有活跃连接发送数据
    for (int i = 0; i < MAX_CONNECTIONS && len > 0; i++)
    {
        if (sock->inners[i] && sock->inners[i]->is_active)
        {
            socket_t *peer = &sockets[sock->inners[i]->peer_fd];

            // 计算可用空间
            uint32_t avail = BUFFER_SIZE - ((peer->inners[i]->buf_tail - peer->inners[i]->buf_head +
                                             BUFFER_SIZE) %
                                            BUFFER_SIZE);
            size_t to_send = MIN(len, avail);

            if (to_send > 0)
            {
                // 处理环形缓冲区
                if (peer->inners[i]->buf_tail + to_send <= BUFFER_SIZE)
                {
                    memcpy(&peer->inners[i]->buffer[peer->inners[i]->buf_tail], src, to_send);
                }
                else
                {
                    size_t first = BUFFER_SIZE - peer->inners[i]->buf_tail;
                    memcpy(&peer->inners[i]->buffer[peer->inners[i]->buf_tail], src, first);
                    memcpy(peer->inners[i]->buffer, src + first, to_send - first);
                }

                peer->inners[i]->buf_tail = (peer->inners[i]->buf_tail + to_send) % BUFFER_SIZE;
                total_sent += to_send;
                len -= to_send;
                src += to_send;
            }
        }
    }

    SPIN_UNLOCK(socket_lock);
    return total_sent ? total_sent : -EAGAIN;
}

int64_t socket_recv(int sockfd, void *buf, size_t len, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    int64_t total_recv = 0;
    uint8_t *dst = buf;

    // 遍历所有活跃连接接收数据
    for (int i = 0; i < MAX_CONNECTIONS && len > 0; i++)
    {
        if (sock->inners[i] && sock->inners[i]->is_active)
        {
            // 计算可用数据量
            uint32_t avail = (sock->inners[i]->buf_tail - sock->inners[i]->buf_head +
                              BUFFER_SIZE) %
                             BUFFER_SIZE;
            size_t to_recv = MIN(len, avail);

            if (to_recv > 0)
            {
                // 处理环形缓冲区
                if (sock->inners[i]->buf_head + to_recv <= BUFFER_SIZE)
                {
                    memcpy(dst, &sock->inners[i]->buffer[sock->inners[i]->buf_head], to_recv);
                }
                else
                {
                    size_t first = BUFFER_SIZE - sock->inners[i]->buf_head;
                    memcpy(dst, &sock->inners[i]->buffer[sock->inners[i]->buf_head], first);
                    memcpy(dst + first, sock->inners[i]->buffer, to_recv - first);
                }

                sock->inners[i]->buf_head = (sock->inners[i]->buf_head + to_recv) % BUFFER_SIZE;
                total_recv += to_recv;
                len -= to_recv;
                dst += to_recv;
            }
        }
    }

    SPIN_UNLOCK(socket_lock);
    return total_recv ? total_recv : -EAGAIN;
}

int64_t socket_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    int64_t total_sent = 0;

    // 遍历所有活跃连接
    for (int conn_idx = 0; conn_idx < MAX_CONNECTIONS; conn_idx++)
    {
        if (!sock->inners[conn_idx] || !sock->inners[conn_idx]->is_active)
            continue;

        socket_t *peer = &sockets[sock->inners[conn_idx]->peer_fd];

        // 处理每个iovec
        for (int i = 0; i < msg->msg_iovlen; i++)
        {
            struct iovec *iov = &msg->msg_iov[i];
            uint8_t *src = iov->iov_base;
            size_t remaining = iov->len;

            while (remaining > 0)
            {
                // 计算可用空间
                uint32_t avail = BUFFER_SIZE - ((peer->inners[conn_idx]->buf_tail -
                                                 peer->inners[conn_idx]->buf_head +
                                                 BUFFER_SIZE) %
                                                BUFFER_SIZE);
                if (avail == 0)
                    break;

                size_t to_send = MIN(remaining, avail);
                uint32_t tail = peer->inners[conn_idx]->buf_tail;

                // 处理环形缓冲区
                if (tail + to_send <= BUFFER_SIZE)
                {
                    memcpy(&peer->inners[conn_idx]->buffer[tail], src, to_send);
                }
                else
                {
                    size_t first = BUFFER_SIZE - tail;
                    memcpy(&peer->inners[conn_idx]->buffer[tail], src, first);
                    memcpy(peer->inners[conn_idx]->buffer, src + first, to_send - first);
                }

                peer->inners[conn_idx]->buf_tail = (tail + to_send) % BUFFER_SIZE;
                src += to_send;
                remaining -= to_send;
                total_sent += to_send;
            }
        }
    }

    SPIN_UNLOCK(socket_lock);
    return total_sent ? total_sent : -EAGAIN;
}

int64_t socket_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    SPIN_LOCK(socket_lock);

    vfs_node_t node = current_task->fds[sockfd];
    if (!node || node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    int64_t total_recv = 0;
    int cur_iov = 0;
    size_t cur_iov_offset = 0;

    // 遍历所有活跃连接
    for (int conn_idx = 0; conn_idx < MAX_CONNECTIONS; conn_idx++)
    {
        if (!sock->inners[conn_idx] || !sock->inners[conn_idx]->is_active)
            continue;

        // 填充来源地址
        if (msg->msg_name && total_recv == 0)
        {
            socket_t *peer = &sockets[sock->inners[conn_idx]->peer_fd];
            struct sockaddr_un *un = msg->msg_name;
            un->sun_family = peer->domain;
            strncpy(un->sun_path, peer->name, sizeof(un->sun_path));
            msg->msg_namelen = sizeof(struct sockaddr_un);
        }

        // 处理所有iovec
        while (cur_iov < msg->msg_iovlen)
        {
            struct iovec *iov = &msg->msg_iov[cur_iov];
            uint8_t *dst = iov->iov_base + cur_iov_offset;
            size_t remaining = iov->len - cur_iov_offset;

            // 计算可用数据
            uint32_t avail = (sock->inners[conn_idx]->buf_tail -
                              sock->inners[conn_idx]->buf_head +
                              BUFFER_SIZE) %
                             BUFFER_SIZE;
            size_t to_recv = MIN(remaining, avail);
            if (to_recv == 0)
                break;

            uint32_t head = sock->inners[conn_idx]->buf_head;

            // 处理环形缓冲区
            if (head + to_recv <= BUFFER_SIZE)
            {
                memcpy(dst, &sock->inners[conn_idx]->buffer[head], to_recv);
            }
            else
            {
                size_t first = BUFFER_SIZE - head;
                memcpy(dst, &sock->inners[conn_idx]->buffer[head], first);
                memcpy(dst + first, sock->inners[conn_idx]->buffer, to_recv - first);
            }

            sock->inners[conn_idx]->buf_head = (head + to_recv) % BUFFER_SIZE;
            total_recv += to_recv;

            // 更新iovec偏移
            if ((cur_iov_offset += to_recv) >= iov->len)
            {
                cur_iov++;
                cur_iov_offset = 0;
            }
        }
    }

    SPIN_UNLOCK(socket_lock);
    return total_recv ? total_recv : -EAGAIN;
}

void socket_ref(socket_t *socket)
{
    SPIN_LOCK(socket_lock);
    socket->ref_count++;
    SPIN_UNLOCK(socket_lock);
}

void socket_unref(socket_t *socket)
{
    SPIN_LOCK(socket_lock);
    if (--socket->ref_count == 0)
    {
        // Close all active connections
        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (socket->inners[i])
            {
                // Notify the peer to close
                socket_t *peer = &sockets[socket->inners[i]->peer_fd];
                for (int j = 0; j < MAX_CONNECTIONS; j++)
                {
                    if (peer->inners[j] && peer->inners[j]->peer_fd == (socket - sockets))
                    {
                        peer->inners[j]->peer_closed = true;
                        break;
                    }
                }

                destroy_connection(socket, i);
            }
        }

        free(socket->pending_conns);
        socket->state = SOCKET_TYPE_UNUSED;
    }
    SPIN_UNLOCK(socket_lock);
}

int socket_socket_close(void *current)
{
    socket_t *socket = current;
    socket_unref(socket);
    return 0;
}

int sys_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    SPIN_LOCK(socket_lock);

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

uint64_t socket_shutdown(uint64_t sockfd, uint64_t how)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
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
    if (how > SHUT_RDWR)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL;
    }

    if (how == SHUT_RDWR)
    {
        socket_socket_close(sock);
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    SPIN_LOCK(socket_lock);

    // 参数校验增强
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fds[fd])
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF;
    }

    vfs_node_t node = current_task->fds[fd];
    if (node->type != file_socket)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTSOCK;
    }

    socket_t *sock = node->handle;
    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    // 查找第一个活跃连接的对端
    int peer_idx = -1;
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (sock->inners[i] && sock->inners[i]->is_active)
        {
            peer_idx = sock->inners[i]->peer_fd;
            break;
        }
    }

    if (peer_idx == -1 || peer_idx >= MAX_SOCKETS)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN;
    }

    // 填充对端地址信息
    socket_t *peer = &sockets[peer_idx];
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    socklen_t len = MIN(*addrlen, sizeof(peer->name) + sizeof(un->sun_family));

    un->sun_family = peer->domain;
    strncpy(un->sun_path, peer->name, len - sizeof(un->sun_family));
    *addrlen = sizeof(struct sockaddr_un);

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int socket_poll(void *file, size_t events)
{
    socket_t *socket = (socket_t *)file;
    int revents = 0;

    SPIN_LOCK(socket_lock);

    if (socket->state == SOCKET_TYPE_LISTENING)
    {
        if (socket->conn_count > 0)
            revents |= EPOLLIN;
        revents |= EPOLLOUT;
    }
    else if (socket->state == SOCKET_TYPE_CONNECTED)
    {
        bool has_data = false;
        bool can_write = true;
        bool peer_closed = false;

        // 检查所有活跃连接
        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (socket->inners[i] && socket->inners[i]->is_active)
            {
                // 检查可读数据
                if (socket->inners[i]->buf_head != socket->inners[i]->buf_tail)
                {
                    has_data = true;
                }

                // 检查可写空间
                uint32_t used = (socket->inners[i]->buf_tail - socket->inners[i]->buf_head +
                                 BUFFER_SIZE) %
                                BUFFER_SIZE;
                if (used >= socket->sndbuf_size)
                {
                    can_write = false;
                }

                // 检查对端关闭
                if (socket->inners[i]->peer_closed)
                {
                    peer_closed = true;
                }
            }
        }

        if (has_data)
            revents |= EPOLLIN;
        if (can_write)
            revents |= EPOLLOUT;
        if (peer_closed)
            revents |= EPOLLHUP;
    }
    else
    {
        revents |= EPOLLHUP;
    }

    SPIN_UNLOCK(socket_lock);
    return revents & events;
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
        .close = (vfs_close_t)socket_socket_close,
        .read = (vfs_read_t)dummy,
        .write = (vfs_write_t)dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .delete = (vfs_del_t)dummy,
        .rename = (vfs_rename_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
        .poll = (vfs_poll_t)socket_poll,
};

void socketfs_init()
{
    memset(sockets, 0, sizeof(sockets));
    socketfs_id = vfs_regist("socketfs", &callback);
    socketfs_root = vfs_node_alloc(rootdir, "sock");
    socketfs_root->type = file_dir;
    socketfs_root->mode = 0644;
    socketfs_root->fsid = socketfs_id;
}
