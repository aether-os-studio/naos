#include <arch/arch.h>
#include <net/net_syscall.h>
#include <net/socket.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>

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
    return unix_socket_getpeername(handle->sock, addr, addrlen);
}

int sys_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    return 0;
}

int sys_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (fd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[fd];

    socket_handle_t *handle = node->node->handle;
    return unix_socket_setsockopt(handle->sock, level, optname, optval, optlen);
}

int sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (fd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[fd];

    socket_handle_t *handle = node->node->handle;
    return unix_socket_getsockopt(handle->sock, level, optname, optval, optlen);
}

int sys_socket(int domain, int type, int protocol)
{
    return socket_socket(domain, type, protocol);
}

int sys_socketpair(int family, int type, int protocol, int *sv)
{
    return unix_socket_pair(type, protocol, sv);
}

int sys_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->bind)
        return handle->op->bind(handle->sock, addr, addrlen);
    return 0;
}

int sys_listen(int sockfd, int backlog)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->listen)
        return handle->op->listen(handle->sock, backlog);
    return 0;
}

int sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->accept)
        return handle->op->accept(handle->sock, addr, addrlen);
    return 0;
}

int sys_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->connect)
        return handle->op->connect(handle->sock, addr, addrlen);
    return 0;
}

int64_t sys_send(int sockfd, void *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendto)
        return handle->op->sendto(node, buff, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t *addrlen)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvfrom)
        return handle->op->recvfrom(node, buf, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendmsg)
        return handle->op->sendmsg(node, msg, flags);
    return 0;
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM)
        return -EBADF;
    fd_t *node = current_task->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvmsg)
        return handle->op->recvmsg(node, msg, flags);
    return 0;
}
