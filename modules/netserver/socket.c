// Copyright (C) 2025-2026  lihanrui2913
#include <lwip/sockets.h>
#include <libs/aether/fs.h>
#include <libs/aether/task.h>
#include <libs/aether/net.h>

#include <lwip/netif.h>
#include <lwip/api.h>
#include <lwip/dhcp.h>
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <lwip/tcpip.h>

struct netif global_netif;

static int realsock_fsid = 0;
#define KERNEL_MSG_DONTWAIT 0x0040

typedef struct real_socket {
    int lwip_fd;
    vfs_node_t node;
    struct llist_header list_node;
} real_socket_t;

static int real_socket_poll(vfs_node_t node, size_t events);
extern socket_op_t real_socket_ops;
DEFINE_LLIST(real_socket_list);
static spinlock_t real_socket_list_lock = SPIN_INIT;

static void real_socket_track(real_socket_t *sock) {
    if (!sock)
        return;
    spin_lock(&real_socket_list_lock);
    if (llist_empty(&sock->list_node))
        llist_append(&real_socket_list, &sock->list_node);
    spin_unlock(&real_socket_list_lock);
}

static void real_socket_untrack(real_socket_t *sock) {
    if (!sock)
        return;
    spin_lock(&real_socket_list_lock);
    if (!llist_empty(&sock->list_node))
        llist_delete(&sock->list_node);
    spin_unlock(&real_socket_list_lock);
}

static inline void real_socket_notify_node(vfs_node_t node, uint32_t events) {
    if (!node || !events)
        return;
    vfs_poll_notify(node, events);
}

static inline void real_socket_notify_sock(real_socket_t *sock,
                                           uint32_t events) {
    if (!sock)
        return;
    real_socket_notify_node(sock->node, events);
}

static void real_socket_notify_all(uint32_t events) {
    if (!events)
        return;
    spin_lock(&real_socket_list_lock);
    real_socket_t *sock, *tmp;
    llist_for_each(sock, tmp, &real_socket_list, list_node) {
        if (sock->node)
            vfs_poll_notify(sock->node, events);
    }
    spin_unlock(&real_socket_list_lock);
}

static inline bool real_socket_is_nonblock(fd_t *fd, int flags) {
    return (fd && (fd->flags & O_NONBLOCK)) || (flags & KERNEL_MSG_DONTWAIT);
}

static int real_socket_wait_ready(fd_t *fd, real_socket_t *sock,
                                  uint32_t events, int flags,
                                  const char *reason) {
    if (!fd || !sock || !sock->node)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    bool nonblock = real_socket_is_nonblock(fd, flags);
    if (real_socket_poll(sock->node, want) & want)
        return 0;
    if (nonblock)
        return -EAGAIN;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(sock->node, &wait) < 0)
        return -EINVAL;

    if (real_socket_poll(sock->node, want) & want) {
        vfs_poll_wait_disarm(&wait);
        return 0;
    }

    const char *block_reason = reason ? reason : "socket_wait";
    int wait_ret = task_block(current_task, TASK_BLOCKING, -1, block_reason);
    vfs_poll_wait_disarm(&wait);
    if (wait_ret == EOK)
        return 0;
    if (wait_ret == ETIMEDOUT)
        return -EAGAIN;
    return -EINTR;
}

struct in_sockaddr {
    sa_family_t sin_family;
    in_port_t sin_port;
    u8_t sin_addr[4];
    char sin_zero[8];
};

void sockaddrLwipToLinux(void *dest_addr, void *src_addr,
                         uint16_t initialFamily) {
    struct in_sockaddr *linuxHandle = (struct in_sockaddr *)dest_addr;
    struct sockaddr_in *handle = (struct sockaddr_in *)src_addr;
    linuxHandle->sin_family = initialFamily;
    linuxHandle->sin_port = handle->sin_port;
    memcpy(linuxHandle->sin_addr, &handle->sin_addr, sizeof(handle->sin_addr));
}

uint16_t sockaddrLinuxToLwip(void *dest_addr, const void *src_addr,
                             uint32_t addrlen) {
    struct in_sockaddr *linuxHandle = (struct in_sockaddr *)src_addr;
    struct sockaddr_in *handle = (struct sockaddr_in *)dest_addr;
    uint16_t initialFamily = linuxHandle->sin_family;
    handle->sin_len = sizeof(struct sockaddr_in);
    handle->sin_family = AF_INET;
    handle->sin_port = linuxHandle->sin_port;
    memcpy(&handle->sin_addr, linuxHandle->sin_addr, sizeof(handle->sin_addr));
    return initialFamily;
}

size_t real_socket_send(uint64_t fd, uint8_t *out, uint64_t limit, int flags) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLOUT, flags, "send");
        if (wait_ret < 0)
            return (size_t)wait_ret;

        lwip_out = lwip_send(sock->lwip_fd, out, limit, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }

    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

size_t real_socket_recv(uint64_t fd, uint8_t *out, uint64_t limit, int flags) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLIN, flags, "recv");
        if (wait_ret < 0)
            return (size_t)wait_ret;

        lwip_out = lwip_recv(sock->lwip_fd, out, limit, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }

    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

size_t real_socket_sendto(uint64_t fd, uint8_t *buff, size_t len, int flags,
                          struct sockaddr_un *dest_addr, socklen_t addrlen) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    if (!addrlen || !dest_addr)
        return real_socket_send(fd, buff, len, flags);

    struct sockaddr_in *aligned = malloc(sizeof(struct sockaddr_in));
    sockaddrLinuxToLwip(aligned, dest_addr, sizeof(struct sockaddr_in));

    int lwipOut = -1;
    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLOUT, flags, "sendto");
        if (wait_ret < 0) {
            free(aligned);
            return (size_t)wait_ret;
        }
        lwipOut = lwip_sendto(sock->lwip_fd, buff, len, flags, (void *)aligned,
                              sizeof(struct sockaddr_in));
        if (lwipOut >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }

    free(aligned);

    if (lwipOut < 0)
        return -errno;
    real_socket_notify_sock(sock, EPOLLOUT);
    return lwipOut;
}

size_t real_socket_recvfrom(uint64_t fd, uint8_t *buff, size_t len, int flags,
                            struct sockaddr_un *addr, socklen_t *addrlen) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    if (!addrlen || !addr)
        return real_socket_recv(fd, buff, len, flags);

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));

    int lwipOut = -1;
    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLIN, flags, "recvfrom");
        if (wait_ret < 0) {
            free(a);
            return (size_t)wait_ret;
        }
        lwipOut =
            lwip_recvfrom(sock->lwip_fd, buff, len, flags, (void *)a, addrlen);
        if (lwipOut >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }

    sockaddrLwipToLinux(addr, a, AF_INET);

    free(a);

    if (lwipOut < 0)
        return -errno;

    *addrlen -= sizeof(uint8_t);

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwipOut;
}

int real_socket_connect(uint64_t fd, const struct sockaddr_un *addr,
                        socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));

    sockaddrLinuxToLwip((void *)a, addr, addrlen);
    if (!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK))
        lwip_fcntl(sock->lwip_fd, F_SETFL, 0);
    int lwip_out =
        lwip_connect(sock->lwip_fd, (void *)a, sizeof(struct sockaddr_in));
    if (!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK))
        lwip_fcntl(sock->lwip_fd, F_SETFL, O_NONBLOCK);
    free(a);
    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT | EPOLLIN);
    return lwip_out;
}

int real_socket_getsockname(uint64_t fd, struct sockaddr_un *addr,
                            socklen_t *addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    int lwip_out = lwip_getsockname(sock->lwip_fd, (void *)a, addrlen);
    sockaddrLwipToLinux(addr, a, AF_INET);
    *addrlen = sizeof(struct in_sockaddr);
    free(a);
    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_getpeername(uint64_t fd, struct sockaddr_un *addr,
                               socklen_t *addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    int lwip_out = lwip_getpeername(sock->lwip_fd, (void *)a, addrlen);
    sockaddrLwipToLinux(addr, a, AF_INET);
    *addrlen = sizeof(struct in_sockaddr);
    free(a);
    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_getsockopt(uint64_t fd, int level, int optname, void *optval,
                              socklen_t *optlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out =
        lwip_getsockopt(sock->lwip_fd, level, optname, optval, optlen);
    if (lwip_out < 0)
        return -errno;
    return lwip_out;
}

size_t real_socket_setsockopt(uint64_t fd, int level, int optname,
                              const void *optval, socklen_t optlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out =
        lwip_setsockopt(sock->lwip_fd, level, optname, optval, optlen);
    if (lwip_out < 0)
        return -errno;
    return lwip_out;
}

size_t real_socket_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    struct sockaddr_in *a = NULL;
    socklen_t alen = 0;
    if (msg->msg_name && msg->msg_namelen) {
        alen = sizeof(struct sockaddr_in);
        a = malloc(alen);
        sockaddrLinuxToLwip((void *)a, msg->msg_name, alen);
    }

    struct msghdr mh = {
        .msg_name = a,
        .msg_namelen = alen,
        .msg_iov = msg->msg_iov,
        .msg_iovlen = msg->msg_iovlen,
        .msg_control = msg->msg_control,
        .msg_controllen = msg->msg_controllen,
        .msg_flags = msg->msg_flags,
    };

    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLOUT, flags, "sendmsg");
        if (wait_ret < 0) {
            free(a);
            return (size_t)wait_ret;
        }

        lwip_out = lwip_sendmsg(sock->lwip_fd, &mh, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }
    free(a);

    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

size_t real_socket_recvmsg(uint64_t fd, struct msghdr *msg, int flags) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    socket_handle_t *handle = fd_entry->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    struct sockaddr_in *a = NULL;
    int alen = 0;
    if (msg->msg_name) {
        a = malloc(sizeof(struct sockaddr_in));
        alen = sizeof(struct sockaddr_in);
    }

    struct msghdr mh = {
        .msg_name = a,
        .msg_namelen = alen,
        .msg_iov = msg->msg_iov,
        .msg_iovlen = msg->msg_iovlen,
        .msg_control = msg->msg_control,
        .msg_controllen = msg->msg_controllen,
        .msg_flags = msg->msg_flags,
    };

    while (true) {
        int wait_ret =
            real_socket_wait_ready(fd_entry, sock, EPOLLIN, flags, "recvmsg");
        if (wait_ret < 0) {
            free(a);
            return (size_t)wait_ret;
        }

        lwip_out = lwip_recvmsg(sock->lwip_fd, &mh, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (real_socket_is_nonblock(fd_entry, flags))
            break;
    }

    if (lwip_out < 0) {
        free(a);
        return -errno;
    }

    if (msg->msg_name) {
        sockaddrLwipToLinux(msg->msg_name, a, AF_INET);
        msg->msg_namelen = sizeof(struct in_sockaddr);
    } else {
        msg->msg_namelen = 0;
    }
    free(a);

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

int real_socket_bind(uint64_t fd, const struct sockaddr_un *addr,
                     socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    sockaddrLinuxToLwip(a, addr, addrlen);
    int out = lwip_bind(sock->lwip_fd, (const struct sockaddr *)a,
                        sizeof(struct sockaddr_in));
    free(a);
    if (out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return out;
}

int real_socket_listen(uint64_t fd, int backlog) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    if (backlog == 0)
        backlog = 1;
    if (backlog < 0)
        backlog = 128;

    int out = lwip_listen(sock->lwip_fd, backlog);
    if (out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLIN | EPOLLOUT);
    return out;
}

static int real_socket_install_fd(int lwip_fd, uint64_t fd_flags,
                                  bool close_on_exec) {
    vfs_node_t socknode = vfs_node_alloc(NULL, "realsock");
    if (!socknode) {
        lwip_close(lwip_fd);
        return -ENOMEM;
    }
    socknode->type = file_socket;
    socknode->fsid = realsock_fsid;
    socknode->refcount++;

    socket_handle_t *handle = calloc(1, sizeof(socket_handle_t));
    if (!handle) {
        lwip_close(lwip_fd);
        vfs_free(socknode);
        return -ENOMEM;
    }
    real_socket_t *real_socket = calloc(1, sizeof(real_socket_t));
    if (!real_socket) {
        free(handle);
        lwip_close(lwip_fd);
        vfs_free(socknode);
        return -ENOMEM;
    }

    real_socket->lwip_fd = lwip_fd;
    real_socket->node = socknode;
    llist_init_head(&real_socket->list_node);

    handle->sock = real_socket;
    handle->op = &real_socket_ops;
    socknode->handle = handle;

    int fdnum = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i])
                continue;
            fd_t *newfd = calloc(1, sizeof(fd_t));
            if (!newfd) {
                fdnum = -ENOMEM;
                break;
            }
            newfd->node = socknode;
            newfd->offset = 0;
            newfd->flags = fd_flags;
            newfd->close_on_exec = close_on_exec;
            current_task->fd_info->fds[i] = newfd;
            handle->fd = newfd;
            fdnum = i;
            break;
        }
    });

    if (fdnum < 0) {
        socknode->handle = NULL;
        free(real_socket);
        free(handle);
        lwip_close(lwip_fd);
        vfs_free(socknode);
        return fdnum;
    }

    real_socket_track(real_socket);
    return fdnum;
}

int real_socket_accept(uint64_t fd, struct sockaddr_un *addr,
                       socklen_t *addrlen, uint64_t flags) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    if (!fd_entry)
        return -EBADF;
    socket_handle_t *handle = fd_entry->node->handle;
    if (!handle || !handle->sock)
        return -EINVAL;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in lwip_addr = {0};
    socklen_t lwip_addrlen = sizeof(struct sockaddr_in);
    int wait_flags = (flags & O_NONBLOCK) ? KERNEL_MSG_DONTWAIT : 0;

    while (true) {
        int wait_ret = real_socket_wait_ready(fd_entry, sock, EPOLLIN,
                                              wait_flags, "accept");
        if (wait_ret < 0)
            return wait_ret;

        lwip_addrlen = sizeof(struct sockaddr_in);
        int new_lwip_fd =
            lwip_accept(sock->lwip_fd, (void *)&lwip_addr, &lwip_addrlen);
        if (new_lwip_fd >= 0) {
            lwip_fcntl(new_lwip_fd, F_SETFL, O_NONBLOCK);
            if (addr && addrlen) {
                sockaddrLwipToLinux(addr, &lwip_addr, AF_INET);
                *addrlen = sizeof(struct in_sockaddr);
            }
            int new_flags = (flags & O_NONBLOCK) ? O_NONBLOCK : 0;
            return real_socket_install_fd(new_lwip_fd, new_flags,
                                          !!(flags & O_CLOEXEC));
        }

        if (errno != EAGAIN)
            return -errno;
        if ((fd_entry->flags & O_NONBLOCK) || (flags & O_NONBLOCK))
            return -EAGAIN;
    }
}

uint64_t real_socket_shutdown(uint64_t fd, uint64_t how) {
    fd_t *fd_entry = current_task->fd_info->fds[fd];
    if (!fd_entry)
        return -EBADF;
    socket_handle_t *handle = fd_entry->node->handle;
    if (!handle || !handle->sock)
        return -EINVAL;
    real_socket_t *sock = handle->sock;

    int ret = lwip_shutdown(sock->lwip_fd, how);
    if (ret < 0)
        return -errno;
    real_socket_notify_sock(sock, EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
    return ret;
}

socket_op_t real_socket_ops = {
    .shutdown = real_socket_shutdown,
    .getsockname = real_socket_getsockname,
    .getpeername = real_socket_getpeername,
    .connect = real_socket_connect,
    .bind = real_socket_bind,
    .accept = real_socket_accept,
    .listen = real_socket_listen,
    .sendto = real_socket_sendto,
    .recvfrom = real_socket_recvfrom,
    .sendmsg = real_socket_sendmsg,
    .recvmsg = real_socket_recvmsg,
    .getsockopt = real_socket_getsockopt,
    .setsockopt = real_socket_setsockopt,
};

static void real_socket_free_handle(vfs_node_t node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;
    real_socket_t *sock = handle->sock;
    if (sock)
        real_socket_untrack(sock);
    free(handle->sock);
    free(handle);
    node->handle = NULL;
}

bool real_socket_close(vfs_node_t node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    if (!handle || !handle->sock)
        return true;
    real_socket_t *sock = handle->sock;

    real_socket_notify_sock(sock, EPOLLERR | EPOLLHUP | EPOLLRDHUP);
    real_socket_untrack(sock);
    lwip_close(sock->lwip_fd);
    real_socket_free_handle(node);

    return true;
}

static int real_socket_poll(vfs_node_t node, size_t events) {
    socket_handle_t *handle = node ? node->handle : NULL;
    if (!handle || !handle->sock)
        return EPOLLNVAL;
    real_socket_t *sock = handle->sock;

    struct pollfd single = {.revents = 0,
                            .events = epoll_to_poll_comp(events),
                            .fd = sock->lwip_fd};

    int ret = lwip_poll(&single, 1, 0);
    if (ret < 0)
        return EPOLLERR;
    if (ret == 0)
        return 0;

    return poll_to_epoll_comp(single.revents);
}

ssize_t real_socket_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    socket_handle_t *handle = fd->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    while (true) {
        int wait_ret = real_socket_wait_ready(fd, sock, EPOLLIN, 0, "read");
        if (wait_ret < 0)
            return wait_ret;

        lwip_out = lwip_read(sock->lwip_fd, addr, size);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (fd->flags & O_NONBLOCK)
            break;
    }

    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

ssize_t real_socket_write(fd_t *fd, const void *addr, size_t offset,
                          size_t size) {
    socket_handle_t *handle = fd->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    while (true) {
        int wait_ret = real_socket_wait_ready(fd, sock, EPOLLOUT, 0, "write");
        if (wait_ret < 0)
            return wait_ret;

        lwip_out = lwip_write(sock->lwip_fd, addr, size);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;
        if (fd->flags & O_NONBLOCK)
            break;
    }

    if (lwip_out < 0)
        return -errno;

    real_socket_notify_sock(sock, EPOLLOUT);
    return lwip_out;
}

static vfs_operations_t real_socket_vfs_ops = {
    .close = real_socket_close,
    .read = real_socket_read,
    .write = real_socket_write,
    .poll = real_socket_poll,
    .free_handle = real_socket_free_handle,
};

bool real_socket_initialized = false;

static void delay(uint64_t ms) {
    uint64_t ns = ms * 1000000;
    uint64_t start = nano_time();
    while (nano_time() - start < ns) {
        arch_pause();
    }
}

void receiver_entry(uint64_t arg) {
    netdev_t *netdev = (netdev_t *)arg;
    uint32_t mtu = netdev->mtu;
    char *buf = alloc_frames_bytes(mtu);
    memset(buf, 0, mtu);

    while (1) {
        int len = netdev_recv(netdev, buf, mtu);
        if (len > 0) {
            struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
            pbuf_take(p, buf, len);
            global_netif.input(p, &global_netif);
            real_socket_notify_all(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP |
                                   EPOLLRDHUP);
        }
        schedule(SCHED_FLAG_YIELD);
    }
}

err_t lwip_dummy_init(struct netif *netif) { return ERR_OK; }

err_t lwip_output(struct netif *netif, struct pbuf *p) {
    uint8_t *complete = malloc(p->tot_len);

    pbuf_copy_partial(p, complete, p->tot_len, 0);

    int ret = netdev_send(get_default_netdev(), complete, p->tot_len);
    if (ret != p->tot_len) {
        printk("netdev_send failed\n");
    }

    free(complete);

    return ERR_OK;
}

void lwip_init_in_thread(void *nicPre) {
    netdev_t *nic = (netdev_t *)nicPre;

    struct netif *this_netif = &global_netif;

    this_netif->state = NULL;
    this_netif->name[0] = 65;
    this_netif->name[1] = 66;
    this_netif->next = NULL;

    netif_add(this_netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL,
              lwip_dummy_init, tcpip_input);

    this_netif->output = etharp_output;
    this_netif->linkoutput = lwip_output;
    this_netif->hwaddr_len = ETHARP_HWADDR_LEN;
    this_netif->hwaddr[0] = nic->mac[0];
    this_netif->hwaddr[1] = nic->mac[1];
    this_netif->hwaddr[2] = nic->mac[2];
    this_netif->hwaddr[3] = nic->mac[3];
    this_netif->hwaddr[4] = nic->mac[4];
    this_netif->hwaddr[5] = nic->mac[5];
    this_netif->mtu = nic->mtu;
    this_netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                        NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP;

    netif_set_default(this_netif);
    netif_set_up(this_netif);

    err_t out = dhcp_start(this_netif);

    if (out != ERR_OK) {
        printk("Failed to start DHCP\n");
        task_exit(0);
    }

    delay(1000);
}

void lwip_check_timeout() {
    int try_bound = 0;
    while (!dhcp_supplied_address(&global_netif)) {
        try_bound++;
        if (try_bound >= 5) {
            printk("DHCP failed to obtain an address\n");
            current_task->should_free = true;
            task_exit(0);
        }
        sys_check_timeouts();
        real_socket_notify_all(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP |
                               EPOLLRDHUP);
        schedule(SCHED_FLAG_YIELD);
        delay(1000);
    }

    real_socket_initialized = true;
    current_task->should_free = true;
    task_exit(0);
}

void real_socket_init_global_netif() {
    netdev_t *dev = get_default_netdev();
    if (dev) {
        task_create("net_receiver", receiver_entry, (uint64_t)dev,
                    KTHREAD_PRIORITY);
        tcpip_init(lwip_init_in_thread, dev);
        task_create("net_checker", (void *)lwip_check_timeout, 0,
                    KTHREAD_PRIORITY);
    }
}

int real_socket_socket(int domain, int type, int protocol) {
    if (!real_socket_initialized)
        return -EHOSTUNREACH;
    int lwip_fd = lwip_socket(domain, type, protocol);
    if (lwip_fd < 0)
        return -errno;
    lwip_fcntl(lwip_fd, F_SETFL, O_NONBLOCK);
    return real_socket_install_fd(lwip_fd, 0, false);
}

int real_socket_v4_init() {
    real_socket_init_global_netif();
    return 0;
}

fs_t socket = {
    .name = "socket",
    .magic = 0,
    .ops = &real_socket_vfs_ops,
    .flags = FS_FLAGS_HIDDEN,
};

void real_socket_init() {
    realsock_fsid = vfs_regist(&socket);

    regist_socket(AF_INET, real_socket_v4_init, real_socket_socket);
}
