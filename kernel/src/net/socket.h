#pragma once

#include <libs/klibc.h>

typedef uint32_t socklen_t;

typedef unsigned short sa_family_t;

#define MAX_SOCKETS 64
#define BUFFER_SIZE 65536
#define SOCKET_NAME_LEN 108

struct sockaddr_un
{
    sa_family_t sun_family;
    char sun_path[SOCKET_NAME_LEN];
};

struct sockaddr
{
    sa_family_t sa_family;
    char sa_data[14];
};

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

struct sock_filter
{
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct sock_fprog
{
    uint16_t len;
    struct sock_filter *filter;
};

typedef struct socket_inner
{
    bool is_active;
    bool peer_closed;            // 新增：标记对端是否关闭
    int peer_fd;                 // 对端socket索引
    uint32_t buf_head;           // 环形缓冲区头
    uint32_t buf_tail;           // 环形缓冲区尾
    uint8_t buffer[BUFFER_SIZE]; // 数据缓冲区
} socket_inner_t;

#define MAX_CONNECTIONS 16

struct timeval;

typedef struct socket
{
    int domain;
    int type;
    int protocol;
    socket_state_t state;
    char name[108]; // UNIX域socket路径

    uint64_t ref_count;

    // 多连接支持
    socket_inner_t *inners[MAX_CONNECTIONS]; // 多连接数组
    int conn_count;                          // 当前活跃连接数

    // poll相关
    int *pending_conns; // 等待连接队列
    int max_pending;    // 最大等待连接数

    // 缓冲区设置
    size_t sndbuf_size; // 发送缓冲区大小
    size_t rcvbuf_size; // 接收缓冲区大小

    // socket选项
    struct
    {
        int reuseaddr;
        int keepalive;
        struct timeval sndtimeo;
        struct timeval rcvtimeo;
        char bind_to_dev[IFNAMSIZ];
        struct linger linger_opt;
        int passcred;
        struct sock_filter *filter;
        size_t filter_len;
    } options;
} socket_t;

int sys_socket_close(void *current);

int socket_getsockname(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen);

// 套接字层级
#define SOL_SOCKET 1

#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_REUSEPORT 15
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO_OLD 20
#define SO_SNDTIMEO_OLD 21

#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SECURITY_ENCRYPTION_NETWORK 24

#define SO_BINDTODEVICE 25

#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_GET_FILTER SO_ATTACH_FILTER

#define SO_PEERNAME 28

#define SO_ACCEPTCONN 30

#define SO_PEERSEC 31
#define SO_PASSSEC 34

#define SO_MARK 36

#define SO_PROTOCOL 38
#define SO_DOMAIN 39

#define SO_RXQ_OVFL 40

#define SO_WIFI_STATUS 41
#define SCM_WIFI_STATUS SO_WIFI_STATUS
#define SO_PEEK_OFF 42

#define SO_NOFCS 43

#define SO_LOCK_FILTER 44

#define SO_SELECT_ERR_QUEUE 45

#define SO_BUSY_POLL 46

#define SO_MAX_PACING_RATE 47

#define SO_BPF_EXTENSIONS 48

#define SO_INCOMING_CPU 49

#define SO_ATTACH_BPF 50
#define SO_DETACH_BPF SO_DETACH_FILTER

#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52

#define SO_CNX_ADVICE 53

#define SCM_TIMESTAMPING_OPT_STATS 54

#define SO_MEMINFO 55

#define SO_INCOMING_NAPI_ID 56

#define SO_COOKIE 57

#define SCM_TIMESTAMPING_PKTINFO 58

#define SO_PEERGROUPS 59

#define SO_ZEROCOPY 60

#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME

#define SO_BINDTOIFINDEX 62

#define SO_TIMESTAMP_OLD 29
#define SO_TIMESTAMPNS_OLD 35
#define SO_TIMESTAMPING_OLD 37

#define SO_TIMESTAMP_NEW 63
#define SO_TIMESTAMPNS_NEW 64
#define SO_TIMESTAMPING_NEW 65

#define SO_RCVTIMEO_NEW 66
#define SO_SNDTIMEO_NEW 67

#define SO_DETACH_REUSEPORT_BPF 68

#define SO_PREFER_BUSY_POLL 69
#define SO_BUSY_POLL_BUDGET 70

#define SO_NETNS_COOKIE 71

#define SO_BUF_LOCK 72

#define SO_RESERVE_MEM 73

#define SO_TXREHASH 74

#define SO_RCVMARK 75

#define SO_PASSPIDFD 76
#define SO_PEERPIDFD 77

#define SO_DEVMEM_LINEAR 78
#define SCM_DEVMEM_LINEAR SO_DEVMEM_LINEAR
#define SO_DEVMEM_DMABUF 79
#define SCM_DEVMEM_DMABUF SO_DEVMEM_DMABUF
#define SO_DEVMEM_DONTNEED 80

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

uint64_t socket_shutdown(uint64_t fd, uint64_t how);
int socket_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen);
int socket_socket(int domain, int type, int protocol);
int socket_socketpair(int family, int type, int protocol, int *sv);
int socket_bind(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen);
int socket_listen(int sockfd, int backlog);
int socket_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen);
int socket_connect(int sockfd, const struct sockaddr_un *addr, socklen_t addrlen);
int64_t socket_send(int sockfd, const void *buf, size_t len, int flags);
int64_t socket_recv(int sockfd, void *buf, size_t len, int flags);
int64_t socket_sendmsg(int sockfd, const struct msghdr *msg, int flags);
int64_t socket_recvmsg(int sockfd, struct msghdr *msg, int flags);

void socket_ref(socket_t *socket);
void socket_unref(socket_t *socket);
