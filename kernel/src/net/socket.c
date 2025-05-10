#include <net/socket.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

// 互斥锁模拟（实际裸机环境需要原子操作实现）
typedef volatile int spinlock_t;
#define SPIN_LOCK(l) while (__sync_lock_test_and_set(&(l), 1))
#define SPIN_UNLOCK(l) __sync_lock_release(&(l))

socket_t sockets[MAX_SOCKETS * 4] = {0};

static spinlock_t socket_lock = 0;

static vfs_node_t socketfs_root = NULL;
static int socketfs_id = 0;

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
        return -EBADFD;
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
    vfs_node_t node = vfs_node_alloc(socketfs_root, strdup(buf));
    node->type = file_socket;
    node->handle = &sockets[sock_id];
    memset(&sockets[sock_id], 0, sizeof(socket_t));
    socket_t *socket = (socket_t *)node->handle;
    strcpy(socket->name, buf);
    socket->buf_head = NULL;
    socket->buf_tail = NULL;
    socket->state = SOCKET_TYPE_UNCONNECTED;
    socket->fd = i;

    current_task->fds[i] = node;

    SPIN_UNLOCK(socket_lock);
    return i;
}

int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        return -EBADF;
    }

    socket_t *sock = node->handle;

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

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        return -EBADF;
    }

    socket_t *sock = node->handle;

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
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        return -EBADF;
    }

    socket_t *listen_sock = node->handle;

    if (!listen_sock || listen_sock->state != SOCKET_TYPE_LISTENING)
    {
        SPIN_UNLOCK(socket_lock);
        return -EINVAL; // EINVAL
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
        return -EBADFD;
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
    socket->buf_head = NULL;
    socket->buf_tail = NULL;
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
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_UNCONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -EBADF; // EBADF
    }

    // 查找目标socket
    const struct sockaddr_un *un = (struct sockaddr_un *)addr;
    for (int i = MAX_FD_NUM; i < MAX_SOCKETS; i++)
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
    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        return -EBADF;
    }

    socket_t *sock = node->handle;

    if (!sock || sock->state != SOCKET_TYPE_CONNECTED)
    {
        SPIN_UNLOCK(socket_lock);
        return -ENOTCONN; // ENOTCONN
    }

    socket_t *peer = current_task->fds[sock->peer_fd];

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
    SPIN_LOCK(socket_lock);

    // 查找socket结构
    vfs_node_t node = current_task->fds[sockfd];
    if (!node)
    {
        return -EBADF;
    }

    socket_t *sock = node->handle;

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

int sys_socket_close(void *current)
{
    // todo
    return 0;
}

static void dummy() {}

static struct vfs_callback callback =
    {
        .mount = (vfs_mount_t)dummy,
        .unmount = (vfs_unmount_t)dummy,
        .open = (vfs_open_t)dummy,
        .close = (vfs_close_t)sys_socket_close,
        .read = dummy,
        .write = dummy,
        .mkdir = (vfs_mk_t)dummy,
        .mkfile = (vfs_mk_t)dummy,
        .stat = (vfs_stat_t)dummy,
        .ioctl = (vfs_ioctl_t)dummy,
};

void socketfs_init()
{
    socketfs_id = vfs_regist("socketfs", &callback);
    socketfs_root = vfs_node_alloc(rootdir, "sock");
    socketfs_root->type = file_dir;
    vfs_node_t node = vfs_child_append(socketfs_root, "sock0", NULL);
    node->type = file_socket;

    int sock_id = -1;
    for (int j = 0; j < MAX_PIPES; j++)
    {
        if (sockets[j].state == SOCKET_TYPE_UNUSED)
        {
            sock_id = j;
            break;
        }
    }

    sockets[sock_id].state = SOCKET_TYPE_UNCONNECTED;
    strcpy(sockets[sock_id].name, ":0");
}
