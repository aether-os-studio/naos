#pragma once

#include <libs/klibc.h>
#include <net/socket.h>

struct sockaddr_nl
{
    uint16_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

#define NETLINK_BUFFER_SIZE 32768

struct netlink_sock
{
    uint32_t portid;
    uint32_t groups;
    uint32_t dst_portid;
    uint32_t dst_groups;
    struct sockaddr_nl *bind_addr;
    char *buffer;
};

extern socket_op_t netlink_ops;

int netlink_socket(int domain, int type, int protocol);
int netlink_socket_pair(int type, int protocol, int *sv);

void netlink_kernel_uevent_send(const char *buf, int len);

void netlink_init();
