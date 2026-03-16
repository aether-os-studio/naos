#pragma once

#include <net/socket.h>

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

uint64_t sys_shutdown(uint64_t fd, uint64_t how);
uint64_t sys_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen);
uint64_t sys_getsockname(int sockfd, struct sockaddr_un *addr,
                         socklen_t *addrlen);
uint64_t sys_socket(int domain, int type, int protocol);
uint64_t sys_socketpair(int family, int type, int protocol, int *sv);
uint64_t sys_bind(int sockfd, const struct sockaddr_un *addr,
                  socklen_t addrlen);
uint64_t sys_listen(int sockfd, int backlog);
uint64_t sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen,
                    uint64_t flags);
uint64_t sys_connect(int sockfd, const struct sockaddr_un *addr,
                     socklen_t addrlen);
int64_t sys_send(int sockfd, void *buff, size_t len, int flags,
                 struct sockaddr_un *dest_addr, socklen_t addrlen);
int64_t sys_recv(int sockfd, void *buff, size_t len, int flags,
                 struct sockaddr_un *dest_addr, socklen_t *addrlen);
int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);

uint64_t sys_setsockopt(int fd, int level, int optname, const void *optval,
                        socklen_t optlen);
uint64_t sys_getsockopt(int fd, int level, int optname, void *optval,
                        socklen_t *optlen);
