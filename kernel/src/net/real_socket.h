#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

typedef uint32_t socklen_t;

#define SOCKET_NAME_LEN 108

struct sockaddr_un {
    uint16_t sun_family;
    char sun_path[SOCKET_NAME_LEN];
};

struct msghdr;

typedef struct socket_op {
    uint64_t (*shutdown)(uint64_t fd, uint64_t how);
    size_t (*getpeername)(uint64_t fd, struct sockaddr_un *addr,
                          socklen_t *addrlen);
    int (*getsockname)(uint64_t fd, struct sockaddr_un *addr,
                       socklen_t *addrlen);
    int (*bind)(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
    int (*listen)(uint64_t fd, int backlog);
    int (*accept)(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen,
                  uint64_t flags);
    int (*connect)(uint64_t fd, const struct sockaddr_un *addr,
                   socklen_t addrlen);
    size_t (*sendto)(uint64_t fd, uint8_t *in, size_t limit, int flags,
                     struct sockaddr_un *addr, uint32_t len);
    size_t (*recvfrom)(uint64_t fd, uint8_t *out, size_t limit, int flags,
                       struct sockaddr_un *addr, uint32_t *len);
    size_t (*recvmsg)(uint64_t fd, struct msghdr *msg, int flags);
    size_t (*sendmsg)(uint64_t fd, const struct msghdr *msg, int flags);
    size_t (*getsockopt)(uint64_t fd, int level, int optname, void *optval,
                         socklen_t *optlen);
    size_t (*setsockopt)(uint64_t fd, int level, int optname,
                         const void *optval, socklen_t optlen);
} socket_op_t;

typedef struct socket_handle {
    fd_t *fd;
    void *sock;
    socket_op_t *op;
} socket_handle_t;

typedef struct real_socket_socket {
    int domain;
    int (*socket)(int domain, int type, int protocol);
} real_socket_socket_t;

#define MAX_SOCKETS_NUM 16

void regist_socket(int domain,
                   int (*socket)(int domain, int type, int protocol));

extern real_socket_socket_t *real_sockets[MAX_SOCKETS_NUM];
extern int socket_num;
