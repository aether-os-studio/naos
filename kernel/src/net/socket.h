#pragma once

#include <libs/klibc.h>
#include <fs/fs_syscall.h>
#include <net/real_socket.h>

#define MAX_SOCKETS 256
#define BUFFER_SIZE 262144

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

struct ucred
{
    int32_t pid;
    uint32_t uid;
    uint32_t gid;
};

#define SCM_RIGHTS 0x01
#define SCM_CREDENTIALS 0x02

typedef struct unix_socket_pair
{
    spinlock_t lock;

    // accept()/server
    bool established;
    int serverFds;
    uint8_t *serverBuff;
    size_t serverBuffPos;
    size_t serverBuffSize;

    struct ucred server;
    struct ucred client;

    char *filename;

    // connect()/client
    int clientFds;
    uint8_t *clientBuff;
    int clientBuffPos;
    int clientBuffSize;

    // msg_control/msg_controllen
    fd_t *pending_files;
    int pending_fds_count;
    int pending_fds_size;

    int reuseaddr;
    int keepalive;
    struct timeval sndtimeo;
    struct timeval rcvtimeo;
    char bind_to_dev[IFNAMSIZ];
    struct linger linger_opt;
    int passcred;
    struct sock_filter *filter;
    size_t filter_len;
    struct ucred peercred;
    bool has_peercred;
} unix_socket_pair_t;

#define MAX_CONNECTIONS 16

typedef struct socket
{
    struct socket *next;

    int domain;
    int protocol;

    int timesOpened;

    // accept()
    bool acceptWouldBlock;

    // bind()
    char *bindAddr;

    // listen()
    int connMax; // if 0, listen() hasn't ran
    int connCurr;
    unix_socket_pair_t **backlog;

    int passcred;

    // connect()
    unix_socket_pair_t *pair;
} socket_t;

bool sys_socket_close(void *current);

int socket_getsockname(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen);

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

#define MSG_OOB 0x0001
#define MSG_PEEK 0x0002
#define MSG_DONTROUTE 0x0004
#define MSG_CTRUNC 0x0008
#define MSG_PROXY 0x0010
#define MSG_TRUNC 0x0020
#define MSG_DONTWAIT 0x0040
#define MSG_EOR 0x0080
#define MSG_WAITALL 0x0100
#define MSG_FIN 0x0200
#define MSG_SYN 0x0400
#define MSG_CONFIRM 0x0800
#define MSG_RST 0x1000
#define MSG_ERRQUEUE 0x2000
#define MSG_NOSIGNAL 0x4000
#define MSG_MORE 0x8000
#define MSG_WAITFORONE 0x10000
#define MSG_BATCH 0x40000
#define MSG_ZEROCOPY 0x4000000
#define MSG_FASTOPEN 0x20000000
#define MSG_CMSG_CLOEXEC 0x40000000

struct msghdr
{
    void *msg_name;        /* ptr to socket address structure */
    int msg_namelen;       /* size of socket address structure */
    struct iovec *msg_iov; /* scatter/gather array */
    size_t msg_iovlen;     /* # elements in msg_iov */
    void *msg_control;     /* ancillary data */
    size_t msg_controllen; /* ancillary data buffer length */
    uint32_t msg_flags;    /* flags on received message */
};

struct cmsghdr
{
    uint64_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

#define __CMSG_LEN(cmsg) (((cmsg)->cmsg_len + sizeof(long) - 1) & ~(long)(sizeof(long) - 1))
#define __CMSG_NEXT(cmsg) ((unsigned char *)(cmsg) + __CMSG_LEN(cmsg))
#define __MHDR_END(mhdr) ((unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen)

#define CMSG_DATA(cmsg) ((unsigned char *)(((struct cmsghdr *)(cmsg)) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) ((cmsg)->cmsg_len < sizeof(struct cmsghdr) ||                                                    \
                                         __CMSG_LEN(cmsg) + sizeof(struct cmsghdr) >= __MHDR_END(mhdr) - (unsigned char *)(cmsg) \
                                     ? 0                                                                                         \
                                     : (struct cmsghdr *)__CMSG_NEXT(cmsg))
#define CMSG_FIRSTHDR(mhdr) ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? (struct cmsghdr *)(mhdr)->msg_control : (struct cmsghdr *)0)

#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1) & (size_t)~(sizeof(size_t) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

extern void socket_on_new_task(uint64_t pid);
extern void socket_on_exit_task(uint64_t pid);
extern void socket_on_dup_file(uint64_t fd, uint64_t newfd);

uint64_t unix_socket_shutdown(uint64_t fd, uint64_t how);
size_t unix_socket_getpeername(uint64_t fd, struct sockaddr_un *addr, uint32_t *len);
int socket_socket(int domain, int type, int protocol);
int unix_socket_pair(int type, int protocol, int *sv);
int socket_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);
int socket_listen(uint64_t fd, int backlog);
int socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags);
int socket_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen);

size_t unix_socket_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen);
size_t unix_socket_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen);
size_t unix_socket_getpeername(uint64_t fdet, struct sockaddr_un *addr, socklen_t *len);

extern int unix_socket_fsid;
extern int unix_accept_fsid;
