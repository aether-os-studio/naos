#pragma once

#include <libs/klibc.h>

typedef int (*netdev_send_t)(void *dev, void *data, uint32_t len);
typedef int (*netdev_recv_t)(void *dev, void *data, uint32_t len);
struct netdev;
typedef void (*netdev_event_cb_t)(struct netdev *dev, uint32_t events,
                                  void *ctx);

#define MAX_NETDEV_NUM 8
#define NETDEV_ETH_FRAME_OVERHEAD 18
#define NETDEV_NAME_LEN 16
#define NETDEV_MAX_EVENT_LISTENERS 8

enum netdev_type {
    NETDEV_TYPE_ETHERNET = 0,
    NETDEV_TYPE_WIFI = 1,
};

enum netdev_event {
    NETDEV_EVENT_REGISTERED = 1U << 0,
    NETDEV_EVENT_ADMIN_UP = 1U << 1,
    NETDEV_EVENT_ADMIN_DOWN = 1U << 2,
    NETDEV_EVENT_LINK_UP = 1U << 3,
    NETDEV_EVENT_LINK_DOWN = 1U << 4,
    NETDEV_EVENT_CONFIG_CHANGED = 1U << 5,
};

typedef struct netdev_listener {
    netdev_event_cb_t cb;
    void *ctx;
} netdev_listener_t;

static inline uint32_t netdev_max_frame_len(uint32_t mtu) {
    return mtu + NETDEV_ETH_FRAME_OVERHEAD;
}

typedef struct netdev {
    char name[NETDEV_NAME_LEN];
    uint8_t mac[6];
    uint32_t mtu;
    uint32_t id;
    uint32_t type;
    bool admin_up;
    bool link_up;
    void *desc;
    netdev_send_t send;
    netdev_recv_t recv;
    spinlock_t lock;
    netdev_listener_t listeners[NETDEV_MAX_EVENT_LISTENERS];
} netdev_t;

netdev_t *netdev_register(const char *name, uint32_t type, void *desc,
                          const uint8_t *mac, uint32_t mtu, netdev_send_t send,
                          netdev_recv_t recv);
void regist_netdev(void *desc, uint8_t *mac, uint32_t mtu, netdev_send_t send,
                   netdev_recv_t recv);

netdev_t *get_default_netdev();
netdev_t *netdev_get_by_name(const char *name);

int netdev_set_name(netdev_t *dev, const char *name);
int netdev_set_link_state(netdev_t *dev, bool link_up);
int netdev_set_admin_state(netdev_t *dev, bool admin_up);
bool netdev_link_is_up(const netdev_t *dev);
bool netdev_admin_is_up(const netdev_t *dev);

int netdev_register_listener(netdev_t *dev, netdev_event_cb_t cb, void *ctx);
void netdev_unregister_listener(netdev_t *dev, netdev_event_cb_t cb, void *ctx);
void netdev_notify(netdev_t *dev, uint32_t events);

int netdev_send(netdev_t *dev, void *data, uint32_t len);
int netdev_recv(netdev_t *dev, void *data, uint32_t len);
