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

struct netlink_sock
{
    uint32_t portid;
    uint32_t groups;
    uint32_t dst_portid;
    uint32_t dst_groups;
    struct sockaddr_nl *bind_addr;
};

extern socket_op_t netlink_ops;

int netlink_socket(int domain, int type, int protocol);
int netlink_socket_pair(int type, int protocol, int *sv);

void netlink_init();
