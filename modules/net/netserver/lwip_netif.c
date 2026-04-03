#include "netserver_internal.h"
#include <net/rtnl.h>
#include <lwip/dns.h>

typedef struct naos_lwip_link {
    netdev_t *netdev;
    bool use_static_ipv4;
    ip4_addr_t static_ipaddr;
    ip4_addr_t static_netmask;
    ip4_addr_t static_gw;
} naos_lwip_link_t;

static naos_lwip_link_t naos_link;
struct netif naos_lwip_netif;

typedef struct naos_lwip_netdev_event {
    bool admin_up;
    bool link_up;
    bool use_static_ipv4;
    ip4_addr_t static_ipaddr;
    ip4_addr_t static_netmask;
    ip4_addr_t static_gw;
} naos_lwip_netdev_event_t;

static void naos_lwip_log_dns_servers(void) {
    for (u8_t i = 0; i < DNS_MAX_SERVERS; i++) {
        const ip_addr_t *server = dns_getserver(i);
        if (server && !ip_addr_isany(server)) {
            printk("netserver: dns[%u] = %s\n", i, ipaddr_ntoa(server));
        }
    }
}

static void naos_lwip_set_fallback_dns(void) {
    const ip_addr_t *server0 = dns_getserver(0);

    if (server0 && !ip_addr_isany(server0)) {
        return;
    }

    ip_addr_t fallback;
    IP_ADDR4(&fallback, 8, 8, 8, 8);
    dns_setserver(0, &fallback);
    printk("netserver: using fallback dns %s\n", ipaddr_ntoa(&fallback));
}

static void naos_lwip_status_callback(struct netif *netif) {
    if (!netif) {
        return;
    }

#if LWIP_IPV4 && LWIP_DHCP
    if (dhcp_supplied_address(netif)) {
        printk("netserver: ipv4=%s netmask=%s gw=%s\n",
               ip4addr_ntoa(netif_ip4_addr(netif)),
               ip4addr_ntoa(netif_ip4_netmask(netif)),
               ip4addr_ntoa(netif_ip4_gw(netif)));
    }
#endif

    naos_lwip_set_fallback_dns();
    naos_lwip_log_dns_servers();
}

static void naos_lwip_apply_link_state(void *arg) {
    naos_lwip_netdev_event_t *event = (naos_lwip_netdev_event_t *)arg;
    ip4_addr_t zero_addr;

    if (!event) {
        return;
    }

    ip4_addr_set_zero(&zero_addr);

    if (!event->admin_up) {
#if LWIP_IPV4 && LWIP_DHCP
        if (!event->use_static_ipv4) {
            netifapi_dhcp_release_and_stop(&naos_lwip_netif);
            netifapi_netif_set_addr(&naos_lwip_netif, &zero_addr, &zero_addr,
                                    &zero_addr);
        }
#endif
        netifapi_netif_set_link_down(&naos_lwip_netif);
        netifapi_netif_set_down(&naos_lwip_netif);
        free(event);
        return;
    }

    netifapi_netif_set_up(&naos_lwip_netif);

    if (!event->link_up) {
#if LWIP_IPV4 && LWIP_DHCP
        if (!event->use_static_ipv4) {
            netifapi_dhcp_release_and_stop(&naos_lwip_netif);
            netifapi_netif_set_addr(&naos_lwip_netif, &zero_addr, &zero_addr,
                                    &zero_addr);
        }
#endif
        netifapi_netif_set_link_down(&naos_lwip_netif);
        free(event);
        return;
    }

    netifapi_netif_set_link_up(&naos_lwip_netif);

#if LWIP_IPV4
    if (event->use_static_ipv4) {
        netifapi_netif_set_addr(&naos_lwip_netif, &event->static_ipaddr,
                                &event->static_netmask, &event->static_gw);
    }
#if LWIP_DHCP
    else {
        netifapi_dhcp_start(&naos_lwip_netif);
    }
#endif
#endif

    naos_lwip_set_fallback_dns();
    free(event);
}

static void naos_lwip_queue_link_state_update(const naos_lwip_link_t *link) {
    naos_lwip_netdev_event_t *event = NULL;

    if (!link || !link->netdev) {
        return;
    }

    event = malloc(sizeof(*event));
    if (!event) {
        return;
    }

    event->admin_up = netdev_admin_is_up(link->netdev);
    event->link_up = netdev_link_is_up(link->netdev);
    event->use_static_ipv4 = link->use_static_ipv4;
    event->static_ipaddr = link->static_ipaddr;
    event->static_netmask = link->static_netmask;
    event->static_gw = link->static_gw;

    if (tcpip_callback(naos_lwip_apply_link_state, event) != ERR_OK) {
        free(event);
    }
}

static void naos_lwip_netdev_event(netdev_t *dev, uint32_t events, void *ctx) {
    naos_lwip_link_t *link = (naos_lwip_link_t *)ctx;

    if (!dev || !link || link->netdev != dev) {
        return;
    }
    if (!(events & (NETDEV_EVENT_ADMIN_UP | NETDEV_EVENT_ADMIN_DOWN |
                    NETDEV_EVENT_LINK_UP | NETDEV_EVENT_LINK_DOWN))) {
        return;
    }

    naos_lwip_queue_link_state_update(link);
}

static err_t naos_lwip_linkoutput(struct netif *netif, struct pbuf *p) {
    naos_lwip_link_t *link = netif ? (naos_lwip_link_t *)netif->state : NULL;
    uint8_t *frame = NULL;
    size_t copied = 0;
    struct pbuf *q = NULL;

    if (!link || !link->netdev || !p) {
        return ERR_IF;
    }

    frame = alloc_frames_bytes(p->tot_len);
    if (!frame) {
        return ERR_MEM;
    }

    for (q = p; q; q = q->next) {
        memcpy(frame + copied, q->payload, q->len);
        copied += q->len;
    }

    if (netdev_send(link->netdev, frame, (uint32_t)p->tot_len) < 0) {
        free_frames_bytes(frame, p->tot_len);
        return ERR_IF;
    }

    free_frames_bytes(frame, p->tot_len);
    return ERR_OK;
}

static err_t naos_lwip_netif_init(struct netif *netif) {
    naos_lwip_link_t *link = netif ? (naos_lwip_link_t *)netif->state : NULL;

    if (!netif || !link || !link->netdev) {
        return ERR_IF;
    }

    if (link->netdev->type == NETDEV_TYPE_WIFI) {
        netif->name[0] = 'w';
        netif->name[1] = 'l';
    } else {
        netif->name[0] = 'e';
        netif->name[1] = 'n';
    }
    netif->hostname = "naos";
    netif->output = etharp_output;
    netif->linkoutput = naos_lwip_linkoutput;
    netif->mtu = (u16_t)link->netdev->mtu;
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, link->netdev->mac, 6);
    netif->flags =
        NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
    if (netdev_admin_is_up(link->netdev)) {
        netif->flags |= NETIF_FLAG_UP;
    }
    if (netdev_link_is_up(link->netdev)) {
        netif->flags |= NETIF_FLAG_LINK_UP;
    }

#if LWIP_IPV6
    netif_create_ip6_linklocal_address(netif, 1);
    netif->ip6_autoconfig_enabled = 1;
#endif

    return ERR_OK;
}

static void naos_lwip_tcpip_init_done(void *arg) {
    sys_sem_t *sem = (sys_sem_t *)arg;
    sys_sem_signal(sem);
}

static uint32_t naos_prefixlen_to_mask_u32(uint8_t prefixlen) {
    if (prefixlen == 0) {
        return 0;
    }
    if (prefixlen >= 32) {
        return 0xFFFFFFFFU;
    }
    return __builtin_bswap32(~((1U << (32 - prefixlen)) - 1));
}

static void naos_lwip_rx_thread(uint64_t arg) {
    naos_lwip_link_t *link = (naos_lwip_link_t *)arg;
    uint32_t max_len = 0;
    uint8_t *buffer = NULL;

    if (!link || !link->netdev) {
        task_exit_thread(0);
    }

    max_len = netdev_max_frame_len(link->netdev->mtu);
    buffer = alloc_frames_bytes(max_len);
    if (!buffer) {
        task_exit_thread(0);
    }

    for (;;) {
        arch_enable_interrupt();

        int len = netdev_recv(link->netdev, buffer, max_len);
        if (len <= 0) {
            schedule(SCHED_FLAG_YIELD);
            continue;
        }

        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
        if (!p) {
            continue;
        }

        if (pbuf_take(p, buffer, (u16_t)len) != ERR_OK) {
            pbuf_free(p);
            continue;
        }

        if (naos_lwip_netif.input(p, &naos_lwip_netif) != ERR_OK) {
            pbuf_free(p);
        }
    }
}

int lwip_module_init() {
    static bool initialized = false;
    sys_sem_t init_sem = NULL;
    ip4_addr_t ipaddr, netmask, gw;
    netdev_t *netdev = NULL;
    int32_t ifindex = 0;
    uint32_t ipv4_addr = 0;
    uint8_t prefixlen = 0;
    uint32_t gateway = 0;
    bool use_static_ipv4 = false;

    if (initialized) {
        return 0;
    }

    netdev = get_default_netdev();
    if (!netdev) {
        printk("netserver: no netdev registered, lwIP stack stays offline\n");
        return -ENODEV;
    }

    if (sys_sem_new(&init_sem, 0) != ERR_OK) {
        return -ENOMEM;
    }

    tcpip_init(naos_lwip_tcpip_init_done, &init_sem);
    sys_arch_sem_wait(&init_sem, 0);
    sys_sem_free(&init_sem);

    memset(&naos_link, 0, sizeof(naos_link));
    memset(&naos_lwip_netif, 0, sizeof(naos_lwip_netif));
    naos_link.netdev = netdev;

    if (rtnl_get_primary_ipv4_config(&ifindex, &ipv4_addr, &prefixlen,
                                     &gateway) == 0) {
        ip4_addr_set_u32(&ipaddr, ipv4_addr);
        ip4_addr_set_u32(&netmask, naos_prefixlen_to_mask_u32(prefixlen));
        ip4_addr_set_u32(&gw, gateway);
        use_static_ipv4 = true;
        naos_link.use_static_ipv4 = true;
        naos_link.static_ipaddr = ipaddr;
        naos_link.static_netmask = netmask;
        naos_link.static_gw = gw;
        printk("netserver: adopting rtnl ipv4=%s/%u gw=%s ifindex=%d\n",
               ip4addr_ntoa(&ipaddr), prefixlen, ip4addr_ntoa(&gw), ifindex);
    } else {
        ip4_addr_set_zero(&ipaddr);
        ip4_addr_set_zero(&netmask);
        ip4_addr_set_zero(&gw);
    }

    if (netifapi_netif_add(&naos_lwip_netif, &ipaddr, &netmask, &gw, &naos_link,
                           naos_lwip_netif_init, tcpip_input) != ERR_OK) {
        return -EIO;
    }

#if LWIP_NETIF_STATUS_CALLBACK
    netif_set_status_callback(&naos_lwip_netif, naos_lwip_status_callback);
#endif

    netifapi_netif_set_default(&naos_lwip_netif);
    netdev_register_listener(netdev, naos_lwip_netdev_event, &naos_link);
    naos_lwip_queue_link_state_update(&naos_link);

    task_create("lwip-rx", naos_lwip_rx_thread, (uint64_t)&naos_link,
                KTHREAD_PRIORITY);

    initialized = true;
    return 0;
}
