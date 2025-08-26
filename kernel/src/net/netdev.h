#pragma once

#include <libs/klibc.h>

typedef int (*netdev_send_t)(void *dev, void *data, uint32_t len);
typedef int (*netdev_recv_t)(void *dev, void *data, uint32_t len);

#define MAX_NETDEV_NUM 8

typedef struct netdev
{
    uint8_t mac[6];
    uint32_t mtu;
    void *desc;
    netdev_send_t send;
    netdev_recv_t recv;
} netdev_t;

void regist_netdev(void *desc, uint8_t *mac, uint32_t mtu, netdev_send_t send, netdev_recv_t recv);

netdev_t *get_default_netdev();

int netdev_send(netdev_t *dev, void *data, uint32_t len);
int netdev_recv(netdev_t *dev, void *data, uint32_t len);
