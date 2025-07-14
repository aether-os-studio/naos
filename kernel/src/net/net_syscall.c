#include <arch/arch.h>
#include <net/net_syscall.h>
#include <net/socket.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <drivers/kernel_logger.h>
#include <net/netlink.h>

uint64_t sys_shutdown(uint64_t fd, uint64_t how)
{
    return 0;
}

int sys_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    if (fd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[fd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->getpeername)
    {
        return handle->op->getpeername(fd, addr, addrlen);
    }
    return -ENOSYS;
}

int sys_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op == &socket_ops || handle->op == &accept_ops)
    {
        socket_t *socket = handle->sock;
        strncpy(addr->sun_path, socket->bindAddr, SOCKET_NAME_LEN);
        *addrlen = strnlen(socket->bindAddr, SOCKET_NAME_LEN);
    }
    else if (handle->op == &netlink_ops)
    {
        struct netlink_sock *socket = handle->sock;
        memcpy(addr, socket->bind_addr, sizeof(struct sockaddr_nl));
    }
    return 0;
}

int sys_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (fd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[fd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->setsockopt)
    {
        return handle->op->setsockopt(fd, level, optname, optval, optlen);
    }
    return -ENOSYS;
}

int sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (fd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[fd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->getsockopt)
    {
        return handle->op->getsockopt(fd, level, optname, optval, optlen);
    }
    return -ENOSYS;
}

int sys_socket(int domain, int type, int protocol)
{
    if (domain == 10 || domain == 2)
        return net_socket(domain, type, protocol);
    else if (domain == 1)
        return socket_socket(domain, type, protocol);
    else if (domain == 16)
        return netlink_socket(domain, type, protocol);
    else
        return -ENOSYS;
}

int sys_socketpair(int family, int type, int protocol, int *sv)
{
    return unix_socket_pair(type, protocol, sv);
}

int sys_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->bind)
        return handle->op->bind(sockfd, addr, addrlen);
    return 0;
}

int sys_listen(int sockfd, int backlog)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->listen)
        return handle->op->listen(sockfd, backlog);
    return 0;
}

int sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->accept)
        return handle->op->accept(sockfd, addr, addrlen, flags);
    return 0;
}

int sys_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->connect)
        return handle->op->connect(sockfd, addr, addrlen);
    return 0;
}

int64_t sys_send(int sockfd, void *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendto)
        return handle->op->sendto(sockfd, buff, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t *addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvfrom)
        return handle->op->recvfrom(sockfd, buf, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendmsg)
        return handle->op->sendmsg(sockfd, msg, flags);
    return 0;
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvmsg)
        return handle->op->recvmsg(sockfd, msg, flags);
    return 0;
}

size_t net_recvmsg(uint64_t fd, struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fds[fd]->node->handle;

    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;
    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr =
            (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));
        if (cnt > 0 && fs_callbacks[current_task->fds[fd]->node->fsid]->poll)
        {
            // check syscalls_fs.c for why this is necessary
            if (!(fs_callbacks[current_task->fds[fd]->node->fsid]->poll(current_task->fds[fd]->node, EPOLLIN) & EPOLLIN))
                return cnt;
        }
        size_t singleCnt = handle->op->recvfrom(
            fd, curr->iov_base, curr->len, noblock ? MSG_DONTWAIT : 0, 0, 0);
        if ((int64_t)(singleCnt) < 0)
            return singleCnt;

        cnt += singleCnt;
    }

    return cnt;
}

size_t net_sendmsg(uint64_t fd, const struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fds[fd]->node->handle;

    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));

        size_t singleCnt = handle->op->sendto(
            fd, curr->iov_base, curr->len,
            noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0)
            return singleCnt;

        cnt += singleCnt;
    }
    return cnt;
}

extern vfs_node_t sockfs_root;
extern int sockfsfd_id;

socket_op_t net_ops = {
    .accept = net_accept,
    .listen = net_listen,
    .bind = net_bind,
    .connect = net_connect,
    .sendto = net_sendto,
    .recvfrom = net_recvfrom,
    .sendmsg = net_sendmsg,
    .recvmsg = net_recvmsg,
    .getpeername = net_getpeername,
    .shutdown = net_shutdown,
    .getsockopt = net_getsockopt,
    .setsockopt = net_setsockopt,
};

int socket_alloc_fd_net()
{
    int fd = 0;
    for (uint64_t i = 0; i < MAX_FD_NUM; i++)
        if (current_task->fds[i] == NULL)
        {
            fd = i;
            break;
        }

    if (fd == 0)
        return 0;

    current_task->fds[fd] = malloc(sizeof(fd_t));
    char buf[256];
    sprintf(buf, "sock%d", sockfsfd_id++);
    current_task->fds[fd]->node = vfs_node_alloc(sockfs_root, buf);
    socket_handle_t *sock = malloc(sizeof(socket_handle_t));
    sock->op = &net_ops;
    sock->sock = NULL;
    current_task->fds[fd]->node->handle = sock;
    current_task->fds[fd]->node->type = file_socket;

    return fd;
}
