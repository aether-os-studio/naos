#pragma once

#include <libs/klibc.h>
#include <task/task.h>

typedef uint32_t socklen_t;

typedef unsigned short sa_family_t;

struct sockaddr_un
{
    sa_family_t sun_family;
    char sun_path[108];
};

struct sockaddr
{
    sa_family_t sa_family;
    char sa_data[14];
};

#define MAX_SOCKETS (16 + MAX_FD_NUM)
#define SOCKET_NAME_LEN 32
#define BUFFER_SIZE 4096

typedef enum
{
    SOCKET_TYPE_UNUSED,
    SOCKET_TYPE_UNCONNECTED,
    SOCKET_TYPE_LISTENING,
    SOCKET_TYPE_CONNECTED
} socket_state_t;

typedef struct
{
    int fd;
    char name[SOCKET_NAME_LEN];
    socket_state_t state;
    int peer_fd;
    char buffer[BUFFER_SIZE];
    uint32_t buf_head;
    uint32_t buf_tail;
} socket_t;

int sys_socket(int domain, int type, int protocol);
int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int64_t sys_send(int sockfd, const void *buf, size_t len, int flags);
int64_t sys_recv(int sockfd, void *buf, size_t len, int flags);
int sys_socket_close(int sockfd);
