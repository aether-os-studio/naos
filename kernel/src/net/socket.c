#include <net/socket.h>

// 简易的实现
static socket_t sockets[MAX_SOCKETS];
static int next_fd = 0;

// 互斥锁模拟（实际裸机环境需要原子操作实现）
typedef volatile int spinlock_t;
#define SPIN_LOCK(l) while (__sync_lock_test_and_set(&(l), 1))
#define SPIN_UNLOCK(l) __sync_lock_release(&(l))

static spinlock_t socket_lock = 0;

int sys_socket(int domain, int type, int protocol)
{
    SPIN_LOCK(socket_lock);

    // 查找空闲socket
    for (int i = MAX_FD_NUM; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].state == SOCKET_TYPE_UNUSED)
        {
            sockets[i].fd = next_fd++;
            sockets[i].state = SOCKET_TYPE_UNCONNECTED;
            sockets[i].peer_fd = -1;
            sockets[i].buf_head = 0;
            sockets[i].buf_tail = 0;
            memset(sockets[i].name, 0, SOCKET_NAME_LEN);

            SPIN_UNLOCK(socket_lock);
            return sockets[i].fd;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -EMFILE; // EMFILE
}

int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    socket_t *sock = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            sock = &sockets[i];
            break;
        }
    }

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF; // EBADF
    }

    // 复制socket名称
    const struct sockaddr_un *un = (struct sockaddr_un *)addr;
    strncpy(sock->name, un->sun_path, SOCKET_NAME_LEN - 1);

    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_listen(int sockfd, int backlog)
{
    SPIN_LOCK(socket_lock);

    socket_t *sock = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            sock = &sockets[i];
            break;
        }
    }

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED || !sock->name[0])
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL; // EINVAL
    }

    sock->state = SOCKET_TYPE_LISTENING;
    SPIN_UNLOCK(socket_lock);
    return 0;
}

int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    // 简化实现：直接返回第一个连接请求
    SPIN_LOCK(socket_lock);

    socket_t *listen_sock = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd &&
            sockets[i].state == SOCKET_TYPE_LISTENING)
        {
            listen_sock = &sockets[i];
            break;
        }
    }

    if (!listen_sock)
    {
        SPIN_UNLOCK(socket_lock);
        return -1; // EINVAL
    }

    // 查找连接请求并创建新socket
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].state == SOCKET_TYPE_CONNECTED &&
            strcmp(sockets[i].name, listen_sock->name) == 0)
        {

            // 创建新的accept socket
            socket_t *new_sock = NULL;
            for (int j = 0; j < MAX_SOCKETS; j++)
            {
                if (sockets[j].state == SOCKET_TYPE_UNUSED)
                {
                    new_sock = &sockets[j];
                    new_sock->fd = next_fd++;
                    new_sock->state = SOCKET_TYPE_CONNECTED;
                    new_sock->peer_fd = sockets[i].fd;
                    sockets[i].peer_fd = new_sock->fd;
                    strcpy(new_sock->name, listen_sock->name);
                    break;
                }
            }

            SPIN_UNLOCK(socket_lock);
            return new_sock ? new_sock->fd : -1;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -1; // EWOULDBLOCK
}

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    socket_t *sock = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            sock = &sockets[i];
            break;
        }
    }

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF; // EBADF
    }

    // 查找目标socket
    const struct sockaddr_un *un = (struct sockaddr_un *)addr;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].state == SOCKET_TYPE_LISTENING &&
            strcmp(sockets[i].name, un->sun_path) == 0)
        {

            sock->state = SOCKET_TYPE_CONNECTED;
            sock->peer_fd = sockets[i].fd;
            strcpy(sock->name, un->sun_path);

            SPIN_UNLOCK(socket_lock);
            return 0;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return -ECONNREFUSED; // ECONNREFUSED
}

int64_t sys_send(int sockfd, const void *buf, size_t len, int flags)
{
    socket_t *sock = NULL;
    socket_t *peer = NULL;

    SPIN_LOCK(socket_lock);
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            sock = &sockets[i];
            break;
        }
    }

    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN; // ENOTCONN
    }

    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sock->peer_fd)
        {
            peer = &sockets[i];
            break;
        }
    }

    if (!peer)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN; // ENOTCONN
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
    socket_t *sock = NULL;

    SPIN_LOCK(socket_lock);
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            sock = &sockets[i];
            break;
        }
    }

    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN; // ENOTCONN
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

int sys_socket_close(int sockfd)
{
    SPIN_LOCK(socket_lock);

    for (int i = MAX_FD_NUM; i < MAX_SOCKETS; i++)
    {
        if (sockets[i].fd == sockfd)
        {
            memset(&sockets[i], 0, sizeof(socket_t));
            sockets[i].state = SOCKET_TYPE_UNUSED;
            break;
        }
    }

    SPIN_UNLOCK(socket_lock);
    return 0;
}
