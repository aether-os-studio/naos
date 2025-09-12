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

/* Netlink message flags */
#define NLM_F_REQUEST 1
#define NLM_F_MULTI 2
#define NLM_F_ACK 4
#define NLM_F_ECHO 8
#define NLM_F_DUMP_INTR 16
#define NLM_F_DUMP_FILTERED 32

#define NLM_F_ROOT 0x100
#define NLM_F_MATCH 0x200
#define NLM_F_ATOMIC 0x400
#define NLM_F_DUMP (NLM_F_ROOT | NLM_F_MATCH)

#define NLM_F_REPLACE 0x100
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NLM_F_APPEND 0x800

/* Netlink message types */
#define NLMSG_NOOP 0x1
#define NLMSG_ERROR 0x2
#define NLMSG_DONE 0x3
#define NLMSG_OVERRUN 0x4
#define NLMSG_MIN_TYPE 0x10

/* Netlink message header */
struct nlmsghdr
{
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

/* Netlink message length macros */
#define NLMSG_ALIGN(len) (((len) + 3) & ~3)
#define NLMSG_LENGTH(len) ((len) + sizeof(struct nlmsghdr))
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh) ((void *)((char *)(nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh, len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                              (struct nlmsghdr *)((char *)(nlh) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh, len) ((len) >= (int)sizeof(struct nlmsghdr) &&       \
                            (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                            (nlh)->nlmsg_len <= (len))

struct sockaddr_nl
{
    uint16_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

#define NETLINK_BUFFER_SIZE 32768

// Netlink socket structure
struct netlink_sock
{
    uint32_t portid;
    uint32_t groups;
    uint32_t dst_portid;
    uint32_t dst_groups;
    struct sockaddr_nl *bind_addr;
    char *buffer;
    size_t buffer_size;
    size_t buffer_pos;
    spinlock_t lock;
};

// Netlink socket operations
extern socket_op_t netlink_ops;

int netlink_socket(int domain, int type, int protocol);
int netlink_socket_pair(int type, int protocol, int *sv);

void netlink_kernel_uevent_send(const char *buf, int len);

void netlink_init();
