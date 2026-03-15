#include "netserver_internal.h"
#include <lwip/err.h>

extern int err_to_errno(err_t err);

int lwip_socket_fsid = 0;

static int lwip_errno_from_err(err_t err) {
    if (err == ERR_OK) {
        return 0;
    }
    return -err_to_errno(err);
}

static inline bool lwip_socket_is_tcp(const lwip_socket_state_t *sock) {
    return sock && ((sock->type & 0xF) == SOCK_STREAM);
}

static inline bool lwip_socket_is_dgram(const lwip_socket_state_t *sock) {
    return sock && ((sock->type & 0xF) == SOCK_DGRAM);
}

static inline bool lwip_socket_is_raw(const lwip_socket_state_t *sock) {
    return sock && ((sock->type & 0xF) == SOCK_RAW);
}

static inline int lwip_socket_recv_avail(lwip_socket_state_t *sock) {
    int avail = 0;
    int queued = 0;

    if (!sock) {
        return 0;
    }
    if (sock->conn) {
        SYS_ARCH_GET(sock->conn->recv_avail, queued);
        if (queued > 0) {
            avail += queued;
        }
    }
    if (sock->rx_pbuf) {
        avail += (int)(sock->rx_pbuf->tot_len - sock->rx_pbuf_offset);
    }
    if (sock->rx_netbuf) {
        avail += (int)(netbuf_len(sock->rx_netbuf) - sock->rx_netbuf_offset);
    }
    return avail;
}

static void lwip_socket_notify(lwip_socket_state_t *sock, uint32_t events) {
    if (sock && sock->node && events) {
        vfs_poll_notify(sock->node, events);
    }
}

static void lwip_socket_event_callback(struct netconn *conn,
                                       enum netconn_evt evt, u16_t len) {
    lwip_socket_state_t *sock = conn ? netconn_get_callback_arg(conn) : NULL;

    LWIP_UNUSED_ARG(len);

    if (!sock) {
        return;
    }

    spin_lock(&sock->event_lock);
    switch (evt) {
    case NETCONN_EVT_RCVPLUS:
        sock->rcvevent++;
        break;
    case NETCONN_EVT_RCVMINUS:
        if (sock->rcvevent > 0) {
            sock->rcvevent--;
        }
        break;
    case NETCONN_EVT_SENDPLUS:
        sock->sendevent = 1;
        break;
    case NETCONN_EVT_SENDMINUS:
        sock->sendevent = 0;
        break;
    case NETCONN_EVT_ERROR:
        sock->errevent = 1;
        break;
    default:
        break;
    }
    spin_unlock(&sock->event_lock);

    if (evt == NETCONN_EVT_SENDPLUS) {
        lwip_socket_notify(sock, EPOLLOUT);
    } else if (evt == NETCONN_EVT_ERROR) {
        lwip_socket_notify(sock, EPOLLERR | EPOLLHUP | EPOLLRDHUP);
    } else {
        lwip_socket_notify(sock, EPOLLIN);
    }
}

static void lwip_socket_free_rx_cache(lwip_socket_state_t *sock) {
    if (!sock) {
        return;
    }
    if (sock->rx_pbuf) {
        if (sock->rx_pbuf_announced > 0) {
            netconn_tcp_recvd(sock->conn, sock->rx_pbuf_announced);
        }
        pbuf_free(sock->rx_pbuf);
        sock->rx_pbuf = NULL;
        sock->rx_pbuf_offset = 0;
        sock->rx_pbuf_announced = 0;
    }
    if (sock->rx_netbuf) {
        netbuf_delete(sock->rx_netbuf);
        sock->rx_netbuf = NULL;
        sock->rx_netbuf_offset = 0;
    }
}

static lwip_socket_state_t *lwip_socket_alloc(struct netconn *conn, int domain,
                                              int type, int protocol) {
    lwip_socket_state_t *sock = calloc(1, sizeof(*sock));
    if (!sock) {
        return NULL;
    }

    sock->conn = conn;
    sock->domain = domain;
    sock->type = type & 0xF;
    sock->protocol = protocol;
    sock->sendevent = 1;
    spin_init(&sock->event_lock);

    if (conn) {
        netconn_set_callback_arg(conn, sock);
    }

    return sock;
}

static vfs_node_t lwip_socket_create_node(lwip_socket_state_t *sock);

static int lwip_socket_install_fd(lwip_socket_state_t *sock, int open_type,
                                  uint64_t accept_flags) {
    int ret = -EMFILE;
    uint64_t slot = 0;
    vfs_node_t node = NULL;
    socket_handle_t *handle = NULL;

    if (!sock) {
        return -EINVAL;
    }

    node = lwip_socket_create_node(sock);
    if (!node) {
        return -ENOMEM;
    }

    with_fd_info_lock(current_task->fd_info, {
        for (slot = 0; slot < MAX_FD_NUM; slot++) {
            if (!current_task->fd_info->fds[slot]) {
                break;
            }
        }

        if (slot == MAX_FD_NUM) {
            break;
        }

        fd_t *new_fd = calloc(1, sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }

        new_fd->node = node;
        if ((open_type & O_NONBLOCK) || (accept_flags & O_NONBLOCK)) {
            new_fd->flags |= O_NONBLOCK;
            if (sock->conn) {
                netconn_set_nonblocking(sock->conn, 1);
            }
        }
        new_fd->close_on_exec = !!((open_type | accept_flags) & O_CLOEXEC);
        current_task->fd_info->fds[slot] = new_fd;
        procfs_on_open_file(current_task, slot);
        ret = (int)slot;
    });

    if (ret < 0) {
        lwip_socket_free_rx_cache(sock);
        if (sock->conn) {
            netconn_delete(sock->conn);
        }
        free(sock);
        vfs_free(node);
        return ret;
    }

    handle = node->handle;
    sock->fd = current_task->fd_info->fds[slot];
    handle->fd = sock->fd;
    return ret;
}

static int lwip_sockaddr_to_ip(const void *addr, socklen_t addrlen, int domain,
                               ip_addr_t *ipaddr, uint16_t *port) {
    if (!addr || !ipaddr || !port) {
        return -EFAULT;
    }

    if (domain == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        if (addrlen < sizeof(*in) || in->sin_family != AF_INET) {
            return -EINVAL;
        }
        ip_addr_set_zero(ipaddr);
        ip_2_ip4(ipaddr)->addr = in->sin_addr.s_addr;
        IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4);
        *port = lwip_ntohs(in->sin_port);
        return 0;
    }

    if (domain == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (addrlen < sizeof(*in6) || in6->sin6_family != AF_INET6) {
            return -EINVAL;
        }
        ip_addr_set_zero(ipaddr);
        memcpy(ip_2_ip6(ipaddr), &in6->sin6_addr, sizeof(struct in6_addr));
        IP_SET_TYPE(ipaddr, IPADDR_TYPE_V6);
        *port = lwip_ntohs(in6->sin6_port);
        return 0;
    }

    return -EAFNOSUPPORT;
}

static int lwip_ip_to_sockaddr(const ip_addr_t *ipaddr, uint16_t port,
                               void *addr, socklen_t *addrlen, int domain) {
    if (!addrlen) {
        return -EFAULT;
    }

    if (domain == AF_INET) {
        struct sockaddr_in out = {0};
        out.sin_family = AF_INET;
        out.sin_port = lwip_htons(port);
        out.sin_addr.s_addr = ip_2_ip4(ipaddr)->addr;
        if (addr && *addrlen) {
            memcpy(addr, &out, MIN((size_t)*addrlen, sizeof(out)));
        }
        *addrlen = sizeof(out);
        return 0;
    }

    if (domain == AF_INET6) {
        struct sockaddr_in6 out6 = {0};
        out6.sin6_family = AF_INET6;
        out6.sin6_port = lwip_htons(port);
        memcpy(&out6.sin6_addr, ip_2_ip6(ipaddr), sizeof(out6.sin6_addr));
        if (addr && *addrlen) {
            memcpy(addr, &out6, MIN((size_t)*addrlen, sizeof(out6)));
        }
        *addrlen = sizeof(out6);
        return 0;
    }

    return -EAFNOSUPPORT;
}

static enum netconn_type lwip_pick_netconn_type(int domain, int type) {
    int sock_type = type & 0xF;

    if (domain == AF_INET) {
        if (sock_type == SOCK_STREAM) {
            return NETCONN_TCP;
        }
        if (sock_type == SOCK_DGRAM) {
            return NETCONN_UDP;
        }
        if (sock_type == SOCK_RAW) {
            return NETCONN_RAW;
        }
    } else if (domain == AF_INET6) {
        if (sock_type == SOCK_STREAM) {
            return NETCONN_TCP_IPV6;
        }
        if (sock_type == SOCK_DGRAM) {
            return NETCONN_UDP_IPV6;
        }
        if (sock_type == SOCK_RAW) {
            return NETCONN_RAW_IPV6;
        }
    }

    return NETCONN_INVALID;
}

static struct netconn *lwip_socket_new_conn(int domain, int type,
                                            int protocol) {
    enum netconn_type conn_type = lwip_pick_netconn_type(domain, type);
    int sock_type = type & 0xF;

    if (conn_type == NETCONN_INVALID) {
        return NULL;
    }

    if (sock_type == SOCK_STREAM) {
        if (protocol != 0 && protocol != IPPROTO_TCP) {
            return NULL;
        }
        return netconn_new_with_proto_and_callback(conn_type, 0,
                                                   lwip_socket_event_callback);
    }

    if (sock_type == SOCK_DGRAM) {
        if (protocol != 0 && protocol != IPPROTO_UDP) {
            return NULL;
        }
        return netconn_new_with_proto_and_callback(conn_type, 0,
                                                   lwip_socket_event_callback);
    }

    if (sock_type == SOCK_RAW) {
        if (!protocol) {
            protocol = (domain == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_RAW;
        }
        return netconn_new_with_proto_and_callback(conn_type, (u8_t)protocol,
                                                   lwip_socket_event_callback);
    }

    return NULL;
}

static int lwip_socket_setsockopt_impl(lwip_socket_state_t *sock, int level,
                                       int optname, const void *optval,
                                       socklen_t optlen) {
    int value = 0;

    if (!sock || !sock->conn) {
        return -EBADF;
    }

    if (optlen >= sizeof(int) && optval) {
        value = *(const int *)optval;
    }

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->reuseaddr = value ? true : false;
            if (value) {
                ip_set_option(sock->conn->pcb.ip, SOF_REUSEADDR);
            } else {
                ip_reset_option(sock->conn->pcb.ip, SOF_REUSEADDR);
            }
            return 0;
        case SO_REUSEPORT:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->reuseport = value ? true : false;
            return 0;
        case SO_KEEPALIVE:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->keepalive = value ? true : false;
            if (value) {
                ip_set_option(sock->conn->pcb.ip, SOF_KEEPALIVE);
            } else {
                ip_reset_option(sock->conn->pcb.ip, SOF_KEEPALIVE);
            }
            return 0;
        case SO_BROADCAST:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->broadcast = value ? true : false;
            if (value) {
                ip_set_option(sock->conn->pcb.ip, SOF_BROADCAST);
            } else {
                ip_reset_option(sock->conn->pcb.ip, SOF_BROADCAST);
            }
            return 0;
        case SO_RCVTIMEO_OLD:
        case SO_RCVTIMEO_NEW:
            if (optlen < sizeof(struct timeval)) {
                return -EINVAL;
            }
            {
                const struct timeval *tv = (const struct timeval *)optval;
                u32_t ms = (u32_t)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
                memcpy(&sock->rcvtimeo, tv, sizeof(*tv));
                netconn_set_recvtimeout(sock->conn, ms);
            }
            return 0;
        case SO_SNDTIMEO_OLD:
        case SO_SNDTIMEO_NEW:
            if (optlen < sizeof(struct timeval)) {
                return -EINVAL;
            }
            {
                const struct timeval *tv = (const struct timeval *)optval;
                s32_t ms = (s32_t)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
                memcpy(&sock->sndtimeo, tv, sizeof(*tv));
                netconn_set_sendtimeout(sock->conn, ms);
            }
            return 0;
        default:
            return -ENOPROTOOPT;
        }
    }

    if (level == IPPROTO_IP) {
        switch (optname) {
        case IP_TTL:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->conn->pcb.ip->ttl = (u8_t)value;
            return 0;
        case IP_TOS:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->conn->pcb.ip->tos = (u8_t)value;
            return 0;
        case IP_PKTINFO:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ip_pktinfo = value ? true : false;
            if (value) {
                sock->conn->flags |= NETCONN_FLAG_PKTINFO;
            } else {
                sock->conn->flags &= ~NETCONN_FLAG_PKTINFO;
            }
            return 0;
        case IP_RECVERR:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ip_recverr = value ? true : false;
            return 0;
        case IP_FREEBIND:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ip_freebind = value ? true : false;
            return 0;
        case IP_BIND_ADDRESS_NO_PORT:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ip_bind_address_no_port = value ? true : false;
            return 0;
        case IP_MTU_DISCOVER:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ip_mtu_discover = value;
            return 0;
        case IP_LOCAL_PORT_RANGE:
            if (optlen < sizeof(uint32_t)) {
                return -EINVAL;
            }
            sock->ip_local_port_range = *(const uint32_t *)optval;
            return 0;
        default:
            return -ENOPROTOOPT;
        }
    }

    if (level == IPPROTO_TCP && optname == TCP_NODELAY &&
        lwip_socket_is_tcp(sock)) {
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (value) {
            tcp_nagle_disable(sock->conn->pcb.tcp);
        } else {
            tcp_nagle_enable(sock->conn->pcb.tcp);
        }
        return 0;
    }

    if (level == IPPROTO_IPV6 && sock->domain == AF_INET6) {
        switch (optname) {
        case IPV6_V6ONLY:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            netconn_set_ipv6only(sock->conn, value ? 1 : 0);
            return 0;
        case IPV6_UNICAST_HOPS:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->conn->pcb.ip->ttl = (u8_t)value;
            return 0;
        case IPV6_RECVPKTINFO:
        case IPV6_PKTINFO:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ipv6_pktinfo = value ? true : false;
            if (value) {
                sock->conn->flags |= NETCONN_FLAG_PKTINFO;
            } else {
                sock->conn->flags &= ~NETCONN_FLAG_PKTINFO;
            }
            return 0;
        case IPV6_RECVERR:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ipv6_recverr = value ? true : false;
            return 0;
        case IPV6_MTU_DISCOVER:
            if (optlen < sizeof(int)) {
                return -EINVAL;
            }
            sock->ipv6_mtu_discover = value;
            return 0;
        default:
            return -ENOPROTOOPT;
        }
    }

    return -ENOPROTOOPT;
}

static int lwip_socket_getsockopt_impl(lwip_socket_state_t *sock, int level,
                                       int optname, void *optval,
                                       socklen_t *optlen) {
    int value = 0;

    if (!sock || !sock->conn || !optlen) {
        return -EBADF;
    }

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_ERROR:
            value = sock->errevent ? err_to_errno(netconn_err(sock->conn)) : 0;
            break;
        case SO_TYPE:
            value = sock->type;
            break;
        case SO_DOMAIN:
            value = sock->domain;
            break;
        case SO_PROTOCOL:
            value = sock->protocol;
            break;
        case SO_ACCEPTCONN:
            value = sock->listening ? 1 : 0;
            break;
        case SO_REUSEADDR:
            value = sock->reuseaddr ? 1 : 0;
            break;
        case SO_REUSEPORT:
            value = sock->reuseport ? 1 : 0;
            break;
        case SO_KEEPALIVE:
            value = sock->keepalive ? 1 : 0;
            break;
        case SO_BROADCAST:
            value = sock->broadcast ? 1 : 0;
            break;
        case SO_RCVTIMEO_OLD:
        case SO_RCVTIMEO_NEW:
            if (*optlen < sizeof(struct timeval)) {
                return -EINVAL;
            }
            memcpy(optval, &sock->rcvtimeo, sizeof(sock->rcvtimeo));
            *optlen = sizeof(sock->rcvtimeo);
            return 0;
        case SO_SNDTIMEO_OLD:
        case SO_SNDTIMEO_NEW:
            if (*optlen < sizeof(struct timeval)) {
                return -EINVAL;
            }
            memcpy(optval, &sock->sndtimeo, sizeof(sock->sndtimeo));
            *optlen = sizeof(sock->sndtimeo);
            break;
        default:
            return -ENOPROTOOPT;
        }

        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = value;
        *optlen = sizeof(int);
        return 0;
    }

    if (level == IPPROTO_IP) {
        switch (optname) {
        case IP_TTL:
            value = sock->conn->pcb.ip->ttl;
            break;
        case IP_TOS:
            value = sock->conn->pcb.ip->tos;
            break;
        case IP_PKTINFO:
            value = sock->ip_pktinfo ? 1 : 0;
            break;
        case IP_RECVERR:
            value = sock->ip_recverr ? 1 : 0;
            break;
        case IP_FREEBIND:
            value = sock->ip_freebind ? 1 : 0;
            break;
        case IP_BIND_ADDRESS_NO_PORT:
            value = sock->ip_bind_address_no_port ? 1 : 0;
            break;
        case IP_MTU_DISCOVER:
            value = sock->ip_mtu_discover;
            break;
        case IP_LOCAL_PORT_RANGE:
            if (*optlen < sizeof(uint32_t)) {
                return -EINVAL;
            }
            *(uint32_t *)optval = sock->ip_local_port_range;
            *optlen = sizeof(uint32_t);
            return 0;
        default:
            return -ENOPROTOOPT;
        }

        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = value;
        *optlen = sizeof(int);
        return 0;
    }

    if (level == IPPROTO_TCP && optname == TCP_NODELAY &&
        lwip_socket_is_tcp(sock)) {
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = tcp_nagle_disabled(sock->conn->pcb.tcp);
        *optlen = sizeof(int);
        return 0;
    }

    if (level == IPPROTO_IPV6 && sock->domain == AF_INET6) {
        switch (optname) {
        case IPV6_V6ONLY:
            value = netconn_get_ipv6only(sock->conn) ? 1 : 0;
            break;
        case IPV6_UNICAST_HOPS:
            value = sock->conn->pcb.ip->ttl;
            break;
        case IPV6_RECVPKTINFO:
        case IPV6_PKTINFO:
            value = sock->ipv6_pktinfo ? 1 : 0;
            break;
        case IPV6_RECVERR:
            value = sock->ipv6_recverr ? 1 : 0;
            break;
        case IPV6_MTU_DISCOVER:
            value = sock->ipv6_mtu_discover;
            break;
        default:
            return -ENOPROTOOPT;
        }

        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = value;
        *optlen = sizeof(int);
        return 0;
    }

    return -ENOPROTOOPT;
}

static int lwip_socket_fetch_tcp(lwip_socket_state_t *sock, int flags) {
    err_t err = ERR_OK;
    u8_t recv_flags = 0;

    if (flags & MSG_DONTWAIT) {
        recv_flags |= NETCONN_DONTBLOCK;
    }

    if (!sock->rx_pbuf) {
        err =
            netconn_recv_tcp_pbuf_flags(sock->conn, &sock->rx_pbuf, recv_flags);
        if (err != ERR_OK) {
            return lwip_errno_from_err(err);
        }
        sock->rx_pbuf_offset = 0;
        sock->rx_pbuf_announced = 0;
    }

    return 0;
}

static int lwip_socket_fetch_datagram(lwip_socket_state_t *sock, int flags) {
    err_t err = ERR_OK;
    u8_t recv_flags = 0;

    if (flags & MSG_DONTWAIT) {
        recv_flags |= NETCONN_DONTBLOCK;
    }

    if (!sock->rx_netbuf) {
        err = netconn_recv_udp_raw_netbuf_flags(sock->conn, &sock->rx_netbuf,
                                                recv_flags);
        if (err != ERR_OK) {
            return lwip_errno_from_err(err);
        }
        sock->rx_netbuf_offset = 0;
    }

    return 0;
}

static ssize_t lwip_socket_copyout_iov(const void *src, size_t src_len,
                                       struct iovec *iov, size_t iovlen,
                                       size_t *copied_total) {
    size_t copied = 0;

    for (size_t i = 0; i < iovlen && copied < src_len; i++) {
        size_t part = MIN(iov[i].len, src_len - copied);
        memcpy(iov[i].iov_base, (const uint8_t *)src + copied, part);
        copied += part;
    }

    if (copied_total) {
        *copied_total = copied;
    }
    return (ssize_t)copied;
}

static size_t lwip_socket_iov_total(const struct iovec *iov, size_t iovlen) {
    size_t total = 0;

    for (size_t i = 0; i < iovlen; i++) {
        total += iov[i].len;
    }
    return total;
}

static ssize_t lwip_socket_recvmsg_common(lwip_socket_state_t *sock,
                                          struct msghdr *msg, int flags) {
    size_t total = 0;
    size_t want = lwip_socket_iov_total(msg->msg_iov, msg->msg_iovlen);

    if (lwip_socket_is_tcp(sock)) {
        int ret = lwip_socket_fetch_tcp(sock, flags);
        if (ret < 0) {
            return ret;
        }
        if (!sock->rx_pbuf) {
            return 0;
        }

        size_t avail = sock->rx_pbuf->tot_len - sock->rx_pbuf_offset;
        size_t take = MIN(avail, want);
        uint8_t *buffer = malloc(take ? take : 1);
        if (!buffer) {
            return -ENOMEM;
        }
        pbuf_copy_partial(sock->rx_pbuf, buffer, (u16_t)take,
                          (u16_t)sock->rx_pbuf_offset);
        lwip_socket_copyout_iov(buffer, take, msg->msg_iov, msg->msg_iovlen,
                                &total);
        free(buffer);

        if (!(flags & MSG_PEEK)) {
            sock->rx_pbuf_offset += total;
            sock->rx_pbuf_announced += total;
            if (sock->rx_pbuf_offset >= sock->rx_pbuf->tot_len) {
                pbuf_free(sock->rx_pbuf);
                sock->rx_pbuf = NULL;
                sock->rx_pbuf_offset = 0;
                if (sock->rx_pbuf_announced > 0) {
                    netconn_tcp_recvd(sock->conn, sock->rx_pbuf_announced);
                    sock->rx_pbuf_announced = 0;
                }
            }
        }

        if (msg->msg_name && msg->msg_namelen > 0) {
            socklen_t namelen = (socklen_t)msg->msg_namelen;
            ip_addr_t addr;
            u16_t port;
            if (netconn_peer(sock->conn, &addr, &port) == ERR_OK) {
                lwip_ip_to_sockaddr(&addr, port, msg->msg_name, &namelen,
                                    sock->domain);
                msg->msg_namelen = namelen;
            } else {
                msg->msg_namelen = 0;
            }
        }

        return (ssize_t)total;
    }

    {
        int ret = lwip_socket_fetch_datagram(sock, flags);
        if (ret < 0) {
            return ret;
        }
        if (!sock->rx_netbuf) {
            return 0;
        }

        size_t avail = netbuf_len(sock->rx_netbuf) - sock->rx_netbuf_offset;
        size_t take = MIN(avail, want);
        uint8_t *buffer = malloc(take ? take : 1);
        if (!buffer) {
            return -ENOMEM;
        }
        netbuf_copy_partial(sock->rx_netbuf, buffer, (u16_t)take,
                            (u16_t)sock->rx_netbuf_offset);
        lwip_socket_copyout_iov(buffer, take, msg->msg_iov, msg->msg_iovlen,
                                &total);
        free(buffer);

        if (msg->msg_name && msg->msg_namelen > 0) {
            socklen_t namelen = (socklen_t)msg->msg_namelen;
            lwip_ip_to_sockaddr(netbuf_fromaddr(sock->rx_netbuf),
                                netbuf_fromport(sock->rx_netbuf), msg->msg_name,
                                &namelen, sock->domain);
            msg->msg_namelen = namelen;
        }

        if (!(flags & MSG_PEEK)) {
            netbuf_delete(sock->rx_netbuf);
            sock->rx_netbuf = NULL;
            sock->rx_netbuf_offset = 0;
        }

        return (ssize_t)total;
    }
}

static ssize_t lwip_socket_sendmsg_common(lwip_socket_state_t *sock,
                                          const struct msghdr *msg, int flags) {
    err_t err = ERR_OK;
    size_t written = 0;

    if (lwip_socket_is_tcp(sock)) {
        u8_t write_flags = NETCONN_COPY;
        if (flags & MSG_DONTWAIT) {
            write_flags |= NETCONN_DONTBLOCK;
        }
        if (flags & MSG_MORE) {
            write_flags |= NETCONN_MORE;
        }

        err = netconn_write_vectors_partly(
            sock->conn, (struct netvector *)msg->msg_iov,
            (u16_t)msg->msg_iovlen, write_flags, &written);
        if (err != ERR_OK) {
            return lwip_errno_from_err(err);
        }
        return (ssize_t)written;
    }

    {
        ip_addr_t dst;
        u16_t port = 0;
        size_t total = lwip_socket_iov_total(msg->msg_iov, msg->msg_iovlen);
        struct netbuf *buf = netbuf_new();
        void *payload = NULL;

        if (!buf) {
            return -ENOMEM;
        }

        if (msg->msg_name && msg->msg_namelen) {
            int ret =
                lwip_sockaddr_to_ip(msg->msg_name, (socklen_t)msg->msg_namelen,
                                    sock->domain, &dst, &port);
            if (ret < 0) {
                netbuf_delete(buf);
                return ret;
            }
        } else if (netconn_peer(sock->conn, &dst, &port) != ERR_OK) {
            netbuf_delete(buf);
            return -EDESTADDRREQ;
        }

        payload = netbuf_alloc(buf, (u16_t)total);
        if (!payload && total) {
            netbuf_delete(buf);
            return -ENOMEM;
        }

        written = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            memcpy((uint8_t *)payload + written, msg->msg_iov[i].iov_base,
                   msg->msg_iov[i].len);
            written += msg->msg_iov[i].len;
        }

        err = netconn_sendto(sock->conn, buf, &dst, port);
        netbuf_delete(buf);
        if (err != ERR_OK) {
            return lwip_errno_from_err(err);
        }
        return (ssize_t)written;
    }
}

static lwip_socket_state_t *lwip_socket_from_fd(uint64_t fd) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd]) {
        return NULL;
    }
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    return handle ? (lwip_socket_state_t *)handle->sock : NULL;
}

static int lwip_socket_socket(int domain, int type, int protocol) {
    struct netconn *conn = NULL;
    lwip_socket_state_t *sock = NULL;

    conn = lwip_socket_new_conn(domain, type, protocol);
    if (!conn) {
        return -ESOCKTNOSUPPORT;
    }

    sock = lwip_socket_alloc(conn, domain, type, protocol);
    if (!sock) {
        netconn_delete(conn);
        return -ENOMEM;
    }

    return lwip_socket_install_fd(sock, type, 0);
}

static int lwip_socket_socketpair(int family, int type, int protocol, int *sv) {
    LWIP_UNUSED_ARG(family);
    LWIP_UNUSED_ARG(type);
    LWIP_UNUSED_ARG(protocol);
    LWIP_UNUSED_ARG(sv);
    return -EOPNOTSUPP;
}

static int lwip_socket_bind(uint64_t fd, const struct sockaddr_un *addr,
                            socklen_t addrlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    ip_addr_t ipaddr;
    u16_t port = 0;
    int ret = 0;

    if (!sock) {
        return -EBADF;
    }

    ret = lwip_sockaddr_to_ip(addr, addrlen, sock->domain, &ipaddr, &port);
    if (ret < 0) {
        return ret;
    }

    return lwip_errno_from_err(netconn_bind(sock->conn, &ipaddr, port));
}

static int lwip_socket_listen(uint64_t fd, int backlog) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);

    if (!sock) {
        return -EBADF;
    }
    if (!lwip_socket_is_tcp(sock)) {
        return -EOPNOTSUPP;
    }

    if (backlog <= 0) {
        backlog = 1;
    }

    if (netconn_listen_with_backlog(sock->conn, (u8_t)MIN(backlog, 255)) !=
        ERR_OK) {
        return -EIO;
    }
    sock->listening = true;
    return 0;
}

static int lwip_socket_accept(uint64_t fd, struct sockaddr_un *addr,
                              socklen_t *addrlen, uint64_t flags) {
    lwip_socket_state_t *listener = lwip_socket_from_fd(fd);
    struct netconn *accepted = NULL;
    lwip_socket_state_t *sock = NULL;
    int newfd = 0;

    if (!listener) {
        return -EBADF;
    }

    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
        return -EINVAL;
    }

    if (netconn_accept(listener->conn, &accepted) != ERR_OK) {
        return -EWOULDBLOCK;
    }

    sock = lwip_socket_alloc(accepted, listener->domain, listener->type,
                             listener->protocol);
    if (!sock) {
        netconn_delete(accepted);
        return -ENOMEM;
    }

    newfd = lwip_socket_install_fd(
        sock, listener->fd ? (int)listener->fd->flags : 0, flags);
    if (newfd < 0) {
        return newfd;
    }

    if (addr && addrlen) {
        ip_addr_t peer_addr;
        u16_t peer_port = 0;
        socklen_t outlen = *addrlen;
        if (netconn_peer(sock->conn, &peer_addr, &peer_port) == ERR_OK) {
            lwip_ip_to_sockaddr(&peer_addr, peer_port, addr, &outlen,
                                sock->domain);
            *addrlen = outlen;
        } else {
            *addrlen = 0;
        }
    }

    return newfd;
}

static int lwip_socket_connect(uint64_t fd, const struct sockaddr_un *addr,
                               socklen_t addrlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    ip_addr_t ipaddr;
    u16_t port = 0;
    int ret = 0;

    if (!sock) {
        return -EBADF;
    }

    ret = lwip_sockaddr_to_ip(addr, addrlen, sock->domain, &ipaddr, &port);
    if (ret < 0) {
        return ret;
    }

    if (lwip_socket_is_tcp(sock)) {
        enum tcp_state state = sock->conn->pcb.tcp->state;

        if (state != CLOSED) {
            if (state == SYN_SENT || state == SYN_RCVD) {
                return -EALREADY;
            }
            return -EISCONN;
        }
    }

    return lwip_errno_from_err(netconn_connect(sock->conn, &ipaddr, port));
}

static size_t lwip_socket_sendto(uint64_t fd, uint8_t *in, size_t limit,
                                 int flags, struct sockaddr_un *addr,
                                 uint32_t len) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    struct iovec iov = {.iov_base = in, .len = limit};
    struct msghdr msg = {0};

    if (!sock) {
        return (size_t)-EBADF;
    }

    msg.msg_name = addr;
    msg.msg_namelen = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return (size_t)lwip_socket_sendmsg_common(sock, &msg, flags);
}

static size_t lwip_socket_recvfrom(uint64_t fd, uint8_t *out, size_t limit,
                                   int flags, struct sockaddr_un *addr,
                                   uint32_t *len) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    struct iovec iov = {.iov_base = out, .len = limit};
    struct msghdr msg = {0};
    socklen_t namelen = len ? *len : 0;
    ssize_t ret = 0;

    if (!sock) {
        return (size_t)-EBADF;
    }

    msg.msg_name = addr;
    msg.msg_namelen = namelen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = lwip_socket_recvmsg_common(sock, &msg, flags);
    if (ret >= 0 && len) {
        *len = (uint32_t)msg.msg_namelen;
    }
    return (size_t)ret;
}

static size_t lwip_socket_sendmsg(uint64_t fd, const struct msghdr *msg,
                                  int flags) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    if (!sock) {
        return (size_t)-EBADF;
    }
    return (size_t)lwip_socket_sendmsg_common(sock, msg, flags);
}

static size_t lwip_socket_recvmsg(uint64_t fd, struct msghdr *msg, int flags) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    if (!sock) {
        return (size_t)-EBADF;
    }
    return (size_t)lwip_socket_recvmsg_common(sock, msg, flags);
}

static int lwip_socket_getsockname(uint64_t fd, struct sockaddr_un *addr,
                                   socklen_t *addrlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    ip_addr_t ipaddr;
    u16_t port = 0;

    if (!sock) {
        return -EBADF;
    }
    if (!addrlen) {
        return -EFAULT;
    }

    if (netconn_addr(sock->conn, &ipaddr, &port) != ERR_OK) {
        return -ENOTCONN;
    }

    return lwip_ip_to_sockaddr(&ipaddr, port, addr, addrlen, sock->domain);
}

static size_t lwip_socket_getpeername(uint64_t fd, struct sockaddr_un *addr,
                                      socklen_t *addrlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    ip_addr_t ipaddr;
    u16_t port = 0;

    if (!sock) {
        return (size_t)-EBADF;
    }
    if (!addrlen) {
        return (size_t)-EFAULT;
    }

    if (netconn_peer(sock->conn, &ipaddr, &port) != ERR_OK) {
        return (size_t)-ENOTCONN;
    }

    return (size_t)lwip_ip_to_sockaddr(&ipaddr, port, addr, addrlen,
                                       sock->domain);
}

static uint64_t lwip_socket_shutdown(uint64_t fd, uint64_t how) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    u8_t shut_rx = 0;
    u8_t shut_tx = 0;

    if (!sock) {
        return -EBADF;
    }
    if (how > SHUT_RDWR) {
        return -EINVAL;
    }

    shut_rx = (how == SHUT_RD || how == SHUT_RDWR) ? 1 : 0;
    shut_tx = (how == SHUT_WR || how == SHUT_RDWR) ? 1 : 0;
    return lwip_errno_from_err(netconn_shutdown(sock->conn, shut_rx, shut_tx));
}

static size_t lwip_socket_setsockopt(uint64_t fd, int level, int optname,
                                     const void *optval, socklen_t optlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    if (!sock) {
        return (size_t)-EBADF;
    }
    return (size_t)lwip_socket_setsockopt_impl(sock, level, optname, optval,
                                               optlen);
}

static size_t lwip_socket_getsockopt(uint64_t fd, int level, int optname,
                                     void *optval, socklen_t *optlen) {
    lwip_socket_state_t *sock = lwip_socket_from_fd(fd);
    if (!sock) {
        return (size_t)-EBADF;
    }
    return (size_t)lwip_socket_getsockopt_impl(sock, level, optname, optval,
                                               optlen);
}

static int lwip_socket_poll(vfs_node_t node, size_t events) {
    socket_handle_t *handle = node ? node->handle : NULL;
    lwip_socket_state_t *sock = handle ? handle->sock : NULL;
    int revents = 0;

    if (!sock) {
        return EPOLLNVAL;
    }

    if ((events & EPOLLIN) &&
        (sock->rcvevent > 0 || lwip_socket_recv_avail(sock) > 0)) {
        revents |= EPOLLIN;
    }

    if ((events & EPOLLOUT) && sock->sendevent) {
        revents |= EPOLLOUT;
    }

    if (sock->errevent || netconn_err(sock->conn) != ERR_OK) {
        revents |= EPOLLERR;
    }

    if (sock->closed) {
        revents |= EPOLLHUP | EPOLLRDHUP;
    }

    return revents;
}

static int lwip_socket_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    socket_handle_t *handle = node ? node->handle : NULL;
    lwip_socket_state_t *sock = handle ? handle->sock : NULL;

    if (!sock) {
        return -EBADF;
    }

    if (cmd == FIONREAD) {
        int value = lwip_socket_recv_avail(sock);
        if (copy_to_user((void *)arg, &value, sizeof(value))) {
            return -EFAULT;
        }
        return 0;
    }

    if (cmd == FIONBIO) {
        int value = 0;

        if (!arg || copy_from_user(&value, (const void *)arg, sizeof(value))) {
            return -EFAULT;
        }

        netconn_set_nonblocking(sock->conn, value ? 1 : 0);
        if (handle->fd) {
            if (value) {
                handle->fd->flags |= O_NONBLOCK;
            } else {
                handle->fd->flags &= ~O_NONBLOCK;
            }
        }
        return 0;
    }

    return -ENOTTY;
}

static bool lwip_socket_close(vfs_node_t node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    lwip_socket_state_t *sock = handle ? handle->sock : NULL;

    if (!sock) {
        return true;
    }

    sock->closed = true;
    lwip_socket_notify(sock, EPOLLHUP | EPOLLERR | EPOLLRDHUP);
    lwip_socket_free_rx_cache(sock);

    if (sock->conn) {
        netconn_set_callback_arg(sock->conn, NULL);
        netconn_delete(sock->conn);
        sock->conn = NULL;
    }

    free(sock);
    free(handle);
    return true;
}

static ssize_t lwip_socket_read(fd_t *fd, void *buf, size_t offset,
                                size_t limit) {
    struct iovec iov = {.iov_base = buf, .len = limit};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    socket_handle_t *handle = fd ? fd->node->handle : NULL;
    lwip_socket_state_t *sock = handle ? handle->sock : NULL;

    LWIP_UNUSED_ARG(offset);

    if (!sock) {
        return -EBADF;
    }

    return lwip_socket_recvmsg_common(sock, &msg, 0);
}

static ssize_t lwip_socket_write(fd_t *fd, const void *buf, size_t offset,
                                 size_t limit) {
    struct iovec iov = {.iov_base = (void *)buf, .len = limit};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    socket_handle_t *handle = fd ? fd->node->handle : NULL;
    lwip_socket_state_t *sock = handle ? handle->sock : NULL;

    LWIP_UNUSED_ARG(offset);

    if (!sock) {
        return -EBADF;
    }

    return lwip_socket_sendmsg_common(sock, &msg, 0);
}

static socket_op_t lwip_socket_ops = {
    .shutdown = lwip_socket_shutdown,
    .getpeername = lwip_socket_getpeername,
    .getsockname = lwip_socket_getsockname,
    .bind = lwip_socket_bind,
    .listen = lwip_socket_listen,
    .accept = lwip_socket_accept,
    .connect = lwip_socket_connect,
    .sendto = lwip_socket_sendto,
    .recvfrom = lwip_socket_recvfrom,
    .recvmsg = lwip_socket_recvmsg,
    .sendmsg = lwip_socket_sendmsg,
    .getsockopt = lwip_socket_getsockopt,
    .setsockopt = lwip_socket_setsockopt,
};

static vfs_operations_t lwip_socket_vfs_ops = {
    .close = lwip_socket_close,
    .read = lwip_socket_read,
    .write = lwip_socket_write,
    .ioctl = lwip_socket_ioctl,
    .poll = lwip_socket_poll,
    .free_handle = vfs_generic_free_handle,
};

static fs_t lwip_socket_fs = {
    .name = "lwip_sockfs",
    .magic = 0,
    .ops = &lwip_socket_vfs_ops,
    .flags = FS_FLAGS_HIDDEN | FS_FLAGS_VIRTUAL,
};

static vfs_node_t lwip_socket_create_node(lwip_socket_state_t *sock) {
    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    socket_handle_t *handle = NULL;

    if (!node) {
        return NULL;
    }

    node->refcount++;
    node->type = file_socket;
    node->mode = 0700;
    node->fsid = lwip_socket_fsid;

    handle = calloc(1, sizeof(*handle));
    if (!handle) {
        vfs_free(node);
        return NULL;
    }

    handle->op = &lwip_socket_ops;
    handle->sock = sock;
    node->handle = handle;
    sock->node = node;
    return node;
}

void lwip_socket_fs_init(void) {
    static bool fs_ready = false;

    if (!fs_ready) {
        lwip_socket_fsid = vfs_regist(&lwip_socket_fs);
        fs_ready = true;
    }
}

extern int lwip_module_init();

void real_socket_v4_init(void) {
    regist_socket(AF_INET, lwip_module_init, lwip_socket_socket,
                  lwip_socket_socketpair);
}

void real_socket_v6_init(void) {
    regist_socket(AF_INET6, lwip_module_init, lwip_socket_socket,
                  lwip_socket_socketpair);
}
