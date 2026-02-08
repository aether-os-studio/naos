#pragma once

#include <libs/klibc.h>
#include <net/socket.h>

/* Netlink protocol family */
#define AF_NETLINK 16
#define PF_NETLINK AF_NETLINK

/* Netlink protocols */
#define NETLINK_ROUTE 0
#define NETLINK_UNUSED 1
#define NETLINK_USERSOCK 2
#define NETLINK_FIREWALL 3
#define NETLINK_SOCK_DIAG 4
#define NETLINK_NFLOG 5
#define NETLINK_XFRM 6
#define NETLINK_SELINUX 7
#define NETLINK_ISCSI 8
#define NETLINK_AUDIT 9
#define NETLINK_FIB_LOOKUP 10
#define NETLINK_CONNECTOR 11
#define NETLINK_NETFILTER 12
#define NETLINK_IP6_FW 13
#define NETLINK_DNRTMSG 14
#define NETLINK_KOBJECT_UEVENT 15
#define NETLINK_GENERIC 16
#define NETLINK_SCSITRANSPORT 18
#define NETLINK_ECRYPTFS 19
#define NETLINK_RDMA 20
#define NETLINK_CRYPTO 21
#define NETLINK_SMC 22

#define NETLINK_BUFFER_SIZE 8192

struct sockaddr_nl {
    uint16_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

// Opaque netlink buffer structure
struct netlink_buffer;

// Netlink packet header for storing sender information in buffer
struct netlink_packet_hdr {
    uint32_t nl_pid;    // Sender's port ID
    uint32_t nl_groups; // Multicast groups mask
    uint32_t length;    // Message data length (excluding header)
};

// Netlink socket structure
struct netlink_sock {
    int domain;
    int type;
    int protocol;
    uint32_t portid;
    uint32_t groups;
    struct sockaddr_nl *bind_addr;
    struct netlink_buffer *buffer; // Circular buffer for messages
    struct sock_fprog *filter;
    spinlock_t lock;
};

// Netlink socket buffer management
struct netlink_buffer {
    char data[NETLINK_BUFFER_SIZE];
    size_t head;
    size_t tail;
    size_t size;
    spinlock_t lock;
};

// Netlink socket operations
extern socket_op_t netlink_ops;

int netlink_socket(int domain, int type, int protocol);
int netlink_socket_pair(int type, int protocol, int *sv);

size_t netlink_buffer_write_packet(struct netlink_sock *sock, const char *data,
                                   size_t len, uint32_t nl_pid,
                                   uint32_t nl_groups);
void netlink_broadcast_to_group(const char *buf, size_t len,
                                uint32_t sender_pid, uint32_t target_groups,
                                int protocol, uint32_t seqnum,
                                const char *devpath);

void netlink_kernel_uevent_send(const char *buf, int len);

void netlink_init();
