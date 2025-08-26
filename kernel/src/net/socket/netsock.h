#pragma once

#include <net/socket.h>

typedef struct netsock
{
    int handle_fd;
} netsock_t;

extern socket_op_t netsock_ops;

struct sockaddr_in
{
    uint16_t sin_family;
    uint16_t sin_port;
    uint8_t sin_addr[4];
    uint8_t sin_zero[8];
};

size_t netsock_getpeername(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen);
int netsock_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
int netsock_listen(uint64_t fd, int backlog);
int netsock_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags);
int netsock_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
size_t netsock_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags, struct sockaddr_un *addr, uint32_t len);
size_t netsock_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags, struct sockaddr_un *addr, uint32_t *len);
size_t netsock_recvmsg(uint64_t fd, struct msghdr *msg, int flags);
size_t netsock_sendmsg(uint64_t fd, const struct msghdr *msg, int flags);
size_t netsock_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen);
size_t netsock_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen);

void netsock_init();

int netsock_socket(int domain, int type, int protocol);
