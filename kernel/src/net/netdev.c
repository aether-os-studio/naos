#include <net/netdev.h>
#include <mm/mm.h>

netdev_t *netdevs[MAX_NETDEV_NUM] = {NULL};

static void netdev_default_name(char *name, uint32_t type, uint32_t id) {
    if (!name) {
        return;
    }

    if (type == NETDEV_TYPE_WIFI) {
        snprintf(name, NETDEV_NAME_LEN, "wlan%u", id);
        return;
    }

    snprintf(name, NETDEV_NAME_LEN, "net%u", id);
}

netdev_t *netdev_register(const char *name, uint32_t type, void *desc,
                          const uint8_t *mac, uint32_t mtu, netdev_send_t send,
                          netdev_recv_t recv) {
    netdev_t *dev = NULL;

    for (uint32_t i = 0; i < MAX_NETDEV_NUM; i++) {
        if (netdevs[i] != NULL) {
            continue;
        }

        dev = calloc(1, sizeof(*dev));
        if (!dev) {
            return NULL;
        }

        dev->id = i;
        dev->type = type;
        dev->desc = desc;
        dev->mtu = mtu;
        dev->send = send;
        dev->recv = recv;
        dev->lock = SPIN_INIT;

        if (name && name[0] != '\0') {
            strncpy(dev->name, name, NETDEV_NAME_LEN - 1);
        } else {
            netdev_default_name(dev->name, type, i);
        }

        if (mac) {
            memcpy(dev->mac, mac, sizeof(dev->mac));
        }

        if (type == NETDEV_TYPE_WIFI) {
            dev->admin_up = false;
            dev->link_up = false;
        } else {
            dev->admin_up = true;
            dev->link_up = true;
        }

        netdevs[i] = dev;
        netdev_notify(dev, NETDEV_EVENT_REGISTERED);
        return dev;
    }

    return NULL;
}

void regist_netdev(void *desc, uint8_t *mac, uint32_t mtu, netdev_send_t send,
                   netdev_recv_t recv) {
    (void)netdev_register(NULL, NETDEV_TYPE_ETHERNET, desc, mac, mtu, send,
                          recv);
}

netdev_t *get_default_netdev() { return netdevs[0]; }

netdev_t *netdev_get_by_name(const char *name) {
    if (!name) {
        return NULL;
    }

    for (uint32_t i = 0; i < MAX_NETDEV_NUM; i++) {
        if (netdevs[i] && strcmp(netdevs[i]->name, name) == 0) {
            return netdevs[i];
        }
    }

    return NULL;
}

int netdev_set_name(netdev_t *dev, const char *name) {
    if (!dev || !name || name[0] == '\0') {
        return -EINVAL;
    }

    spin_lock(&dev->lock);
    strncpy(dev->name, name, NETDEV_NAME_LEN - 1);
    dev->name[NETDEV_NAME_LEN - 1] = '\0';
    spin_unlock(&dev->lock);

    netdev_notify(dev, NETDEV_EVENT_CONFIG_CHANGED);
    return 0;
}

int netdev_set_link_state(netdev_t *dev, bool link_up) {
    bool changed = false;

    if (!dev) {
        return -EINVAL;
    }

    spin_lock(&dev->lock);
    changed = dev->link_up != link_up;
    dev->link_up = link_up;
    spin_unlock(&dev->lock);

    if (changed) {
        netdev_notify(dev,
                      link_up ? NETDEV_EVENT_LINK_UP : NETDEV_EVENT_LINK_DOWN);
    }

    return 0;
}

int netdev_set_admin_state(netdev_t *dev, bool admin_up) {
    bool changed = false;

    if (!dev) {
        return -EINVAL;
    }

    spin_lock(&dev->lock);
    changed = dev->admin_up != admin_up;
    dev->admin_up = admin_up;
    spin_unlock(&dev->lock);

    if (changed) {
        netdev_notify(dev, admin_up ? NETDEV_EVENT_ADMIN_UP
                                    : NETDEV_EVENT_ADMIN_DOWN);
    }

    return 0;
}

bool netdev_link_is_up(const netdev_t *dev) {
    return dev ? dev->link_up : false;
}

bool netdev_admin_is_up(const netdev_t *dev) {
    return dev ? dev->admin_up : false;
}

int netdev_register_listener(netdev_t *dev, netdev_event_cb_t cb, void *ctx) {
    if (!dev || !cb) {
        return -EINVAL;
    }

    spin_lock(&dev->lock);
    for (uint32_t i = 0; i < NETDEV_MAX_EVENT_LISTENERS; i++) {
        if (dev->listeners[i].cb == NULL) {
            dev->listeners[i].cb = cb;
            dev->listeners[i].ctx = ctx;
            spin_unlock(&dev->lock);
            return 0;
        }
    }
    spin_unlock(&dev->lock);

    return -ENOSPC;
}

void netdev_unregister_listener(netdev_t *dev, netdev_event_cb_t cb,
                                void *ctx) {
    if (!dev || !cb) {
        return;
    }

    spin_lock(&dev->lock);
    for (uint32_t i = 0; i < NETDEV_MAX_EVENT_LISTENERS; i++) {
        if (dev->listeners[i].cb == cb && dev->listeners[i].ctx == ctx) {
            dev->listeners[i].cb = NULL;
            dev->listeners[i].ctx = NULL;
            break;
        }
    }
    spin_unlock(&dev->lock);
}

void netdev_notify(netdev_t *dev, uint32_t events) {
    netdev_listener_t listeners[NETDEV_MAX_EVENT_LISTENERS];

    if (!dev || !events) {
        return;
    }

    spin_lock(&dev->lock);
    memcpy(listeners, dev->listeners, sizeof(listeners));
    spin_unlock(&dev->lock);

    for (uint32_t i = 0; i < NETDEV_MAX_EVENT_LISTENERS; i++) {
        if (listeners[i].cb) {
            listeners[i].cb(dev, events, listeners[i].ctx);
        }
    }
}

int netdev_send(netdev_t *dev, void *data, uint32_t len) {
    if (dev == NULL || data == NULL) {
        return -EINVAL;
    }

    if (len == 0) {
        return 0;
    }
    return dev->send(dev->desc, data, len);
}

int netdev_recv(netdev_t *dev, void *data, uint32_t len) {
    if (dev == NULL || data == NULL) {
        return -EINVAL;
    }

    if (len == 0) {
        return 0;
    }

    int ret = dev->recv(dev->desc, data, len);

    return ret;
}
