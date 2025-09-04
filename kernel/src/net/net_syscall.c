#include <arch/arch.h>
#include <net/net_syscall.h>
#include <net/real_socket.h>
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
    fd_t *node = current_task->fd_info->fds[fd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->getpeername)
    {
        return handle->op->getpeername(fd, addr, addrlen);
    }
    return -ENOSYS;
}

int sys_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    if (sockfd < 0 || sockfd > MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[sockfd]->node->handle;
    if (handle->op->getsockname)
        return handle->op->getsockname(sockfd, addr, addrlen);
    return -ENOSYS;
}

int sys_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (fd < 0 || fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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
    fd_t *node = current_task->fd_info->fds[fd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->getsockopt)
    {
        return handle->op->getsockopt(fd, level, optname, optval, optlen);
    }
    return -ENOSYS;
}

int sys_socket(int domain, int type, int protocol)
{
    int fd = -EAFNOSUPPORT;
    if (domain == 1)
        fd = socket_socket(domain, type, protocol);
    else if (domain == 16)
        fd = netlink_socket(domain, type, protocol);
    else
        for (int i = 0; i < socket_num; i++)
        {
            if (real_sockets[i]->domain == domain)
            {
                fd = real_sockets[i]->socket(domain, type & 0xff, protocol);
            }
        }

    if (!(fd < 0))
    {
        if (type & O_CLOEXEC)
            current_task->fd_info->fds[fd]->flags |= O_CLOEXEC;
        if (type & O_NONBLOCK)
            current_task->fd_info->fds[fd]->flags |= O_NONBLOCK;
    }

    return fd;
}

int sys_socketpair(int family, int type, int protocol, int *sv)
{
    if (family == 1)
    {
        return unix_socket_pair(type, protocol, sv);
    }
    return -ENOSYS;
}

int sys_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->bind)
        return handle->op->bind(sockfd, addr, addrlen);
    return 0;
}

int sys_listen(int sockfd, int backlog)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->listen)
        return handle->op->listen(sockfd, backlog);
    return 0;
}

int sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->accept)
        return handle->op->accept(sockfd, addr, addrlen, flags);
    return 0;
}

int sys_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->connect)
        return handle->op->connect(sockfd, addr, addrlen);
    return 0;
}

int64_t sys_send(int sockfd, void *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendto)
        return handle->op->sendto(sockfd, buff, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t *addrlen)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvfrom)
        return handle->op->recvfrom(sockfd, buf, len, flags, dest_addr, addrlen);
    return 0;
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->sendmsg)
        return handle->op->sendmsg(sockfd, msg, flags);
    return 0;
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (sockfd >= MAX_FD_NUM || !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];

    socket_handle_t *handle = node->node->handle;
    if (handle->op->recvmsg)
        return handle->op->recvmsg(sockfd, msg, flags);
    return 0;
}
