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

#define MAX_SOCKETS 64
#define SOCKET_NAME_LEN 32
#define BUFFER_SIZE 4096

typedef enum
{
    SOCKET_TYPE_UNUSED,
    SOCKET_TYPE_UNCONNECTED,
    SOCKET_TYPE_LISTENING,
    SOCKET_TYPE_CONNECTED
} socket_state_t;

struct linger
{
    int l_onoff;  // linger active
    int l_linger; // linger time (seconds)
};

#define IFNAMSIZ 16

typedef struct
{
    int fd;
    char name[SOCKET_NAME_LEN];
    socket_state_t state;
    int peer_fd;
    char buffer[BUFFER_SIZE];
    uint32_t buf_head;
    uint32_t buf_tail;
    uint64_t type;
    int64_t protocol;
    struct
    {
        int reuseaddr;              // SO_REUSEADDR
        int keepalive;              // SO_KEEPALIVE
        int sndtimeo;               // SO_SNDTIMEO
        int rcvtimeo;               // SO_RCVTIMEO
        struct linger linger_opt;   // SO_LINGER
        char bind_to_dev[IFNAMSIZ]; // SO_BINDTODEVICE
    } options;
} socket_t;

int sys_socket(int domain, int type, int protocol);
int sys_socketpair(int family, int type, int protocol, int *sv);
int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int64_t sys_send(int sockfd, const void *buf, size_t len, int flags);
int64_t sys_recv(int sockfd, void *buf, size_t len, int flags);
int sys_socket_close(void *current);

int sys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

// 套接字层级
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define SO_KEEPALIVE 9
#define SO_SNDTIMEO 21
#define SO_RCVTIMEO 20

// 套接字选项
#define SO_REUSEADDR 2 // 允许地址重用
#define SO_TYPE 3      // 获取套接字类型
#define SO_ERROR 4     // 获取并清除错误状态
#define SO_KEEPALIVE 9 // 保持连接检测
#define SO_BINDTODEVICE 16
#define SO_PROTOCOL 17 // 获取套接字协议类型
#define SO_SNDTIMEO 21 // 发送超时
#define SO_RCVTIMEO 20 // 接收超时
#define SO_LINGER 26

int sys_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int sys_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

struct msghdr
{
    void *msg_name;           // 套接字地址（用于未连接套接字）
    socklen_t msg_namelen;    // 地址长度
    struct iovec *msg_iov;    // 分散/聚集数组的指针
    int msg_iovlen;           // iovec元素数量
    void *msg_control;        // 辅助数据（控制信息）
    socklen_t msg_controllen; // 辅助数据长度
    int msg_flags;            // 接收消息的标志
};

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
