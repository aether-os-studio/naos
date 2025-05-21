#include <arch/arch.h>
#include <net/net_syscall.h>

uint64_t sys_shutdown(uint64_t fd, uint64_t how)
{
    return socket_shutdown(fd, how);
}

int sys_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    return socket_getpeername(fd, addr, addrlen);
}

int sys_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    return socket_getsockname(sockfd, addr, addrlen);
}

int sys_socket(int domain, int type, int protocol)
{
    return socket_socket(domain, type, protocol);
}

int sys_socketpair(int family, int type, int protocol, int *sv)
{
    return socket_socketpair(family, type, protocol, sv);
}

int sys_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    return socket_bind(sockfd, addr, addrlen);
}

int sys_listen(int sockfd, int backlog)
{
    return socket_listen(sockfd, backlog);
}

int sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    return socket_accept(sockfd, addr, addrlen);
}

int sys_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    return socket_connect(sockfd, addr, addrlen);
}

int64_t sys_send(int sockfd, const void *buf, size_t len, int flags)
{
    return socket_send(sockfd, buf, len, flags);
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags)
{
    return socket_recv(sockfd, buf, len, flags);
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    return socket_sendmsg(sockfd, msg, flags);
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    return socket_recvmsg(sockfd, msg, flags);
}
