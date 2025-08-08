#pragma once

#include <libs/klibc.h>
#include <net/socket.h>

struct sockaddr_nl
{
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

#define NETLINK_ROUTE 0     /* Routing/device hook				*/
#define NETLINK_UNUSED 1    /* Unused number				*/
#define NETLINK_USERSOCK 2  /* Reserved for user mode socket protocols 	*/
#define NETLINK_FIREWALL 3  /* Unused number, formerly ip_queue		*/
#define NETLINK_SOCK_DIAG 4 /* socket monitoring				*/
#define NETLINK_NFLOG 5     /* netfilter/iptables ULOG */
#define NETLINK_XFRM 6      /* ipsec */
#define NETLINK_SELINUX 7   /* SELinux event notifications */
#define NETLINK_ISCSI 8     /* Open-iSCSI */
#define NETLINK_AUDIT 9     /* auditing */
#define NETLINK_FIB_LOOKUP 10
#define NETLINK_CONNECTOR 11
#define NETLINK_NETFILTER 12 /* netfilter subsystem */
#define NETLINK_IP6_FW 13
#define NETLINK_DNRTMSG 14        /* DECnet routing messages */
#define NETLINK_KOBJECT_UEVENT 15 /* Kernel messages to userspace */
#define NETLINK_GENERIC 16
/* leave room for NETLINK_DM (DM Events) */
#define NETLINK_SCSITRANSPORT 18 /* SCSI Transports */
#define NETLINK_ECRYPTFS 19
#define NETLINK_RDMA 20
#define NETLINK_CRYPTO 21 /* Crypto layer */
#define NETLINK_SMC 22    /* SMC monitoring */

struct netlink_sock
{
    struct sockaddr_nl *bind_addr;
    spinlock_t lock;
    int protocol;
};

struct nlmsghdr
{
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh) ((void *)(((char *)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh, len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                              (struct nlmsghdr *)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh, len) ((len) >= (int)sizeof(struct nlmsghdr) &&       \
                            (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                            (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh, len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

extern socket_op_t netlink_ops;

int netlink_socket(int domain, int type, int protocol);
int netlink_socket_pair(int type, int protocol, int *sv);

void netlink_init();
