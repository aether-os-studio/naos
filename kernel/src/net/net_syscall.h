#pragma once

#include <net/socket.h>

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

uint64_t sys_shutdown(uint64_t fd, uint64_t how);
int sys_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen);
int sys_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen);
int sys_socket(int domain, int type, int protocol);
int sys_socketpair(int family, int type, int protocol, int *sv);
int sys_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags);
int sys_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen);
int64_t sys_send(int sockfd, void *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t addrlen);
int64_t sys_recv(int sockfd, void *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t *addrlen);
int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);

extern int net_socket(int domain, int type, int protocol);
extern uint64_t net_shutdown(uint64_t fd, uint64_t how);
extern size_t net_getpeername(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen);
extern int net_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
extern int net_listen(uint64_t fd, int backlog);
extern int net_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags);
extern int net_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
extern size_t net_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags, struct sockaddr_un *addr, uint32_t len);
extern size_t net_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags, struct sockaddr_un *addr, uint32_t *len);
extern size_t net_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen);
extern size_t net_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen);
size_t net_recvmsg(uint64_t fd, struct msghdr *msg, int flags);
size_t net_sendmsg(uint64_t fd, const struct msghdr *msg, int flags);

int sys_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
