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

typedef struct real_socket
{
    int lwip_fd;
} real_socket_t;

struct in_sockaddr
{
    sa_family_t sin_family;
    in_port_t sin_port;
    u8_t sin_addr[4];
    char sin_zero[8];
};

void sockaddrLwipToLinux(void *dest_addr, void *src_addr, uint16_t initialFamily)
{
    struct in_sockaddr *linuxHandle = (struct in_sockaddr *)dest_addr;
    struct sockaddr_in *handle = (struct sockaddr_in *)src_addr;
    linuxHandle->sin_family = initialFamily;
    linuxHandle->sin_port = handle->sin_port;
    memcpy(linuxHandle->sin_addr, &handle->sin_addr, sizeof(handle->sin_addr));
}

uint16_t sockaddrLinuxToLwip(void *dest_addr, void *src_addr, uint32_t addrlen)
{
    struct in_sockaddr *linuxHandle = (struct in_sockaddr *)src_addr;
    struct sockaddr_in *handle = (struct sockaddr_in *)dest_addr;
    uint16_t initialFamily = linuxHandle->sin_family;
    handle->sin_len = sizeof(struct sockaddr_in);
    handle->sin_family = AF_INET;
    handle->sin_port = linuxHandle->sin_port;
    memcpy(&handle->sin_addr, linuxHandle->sin_addr, sizeof(handle->sin_addr));
    return initialFamily;
}

size_t real_socket_send(uint64_t fd, uint8_t *out, uint64_t limit, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLOUT) & EPOLLOUT))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK || flags & 0x40)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_send(sock->lwip_fd, out, limit, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_recv(uint64_t fd, uint8_t *out, uint64_t limit, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK || flags & 0x40)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_recv(sock->lwip_fd, out, limit, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_sendto(uint64_t fd, uint8_t *buff, size_t len, int flags, struct sockaddr_un *dest_addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    if (!addrlen || !dest_addr)
        return real_socket_send(fd, buff, len, flags);

    arch_enable_interrupt();

    struct sockaddr *aligned = malloc(addrlen);
    memcpy(aligned, dest_addr, addrlen);
    uint16_t initialFamily = sockaddrLinuxToLwip(aligned, dest_addr, addrlen);

    int lwipOut = -1;
    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLOUT) & EPOLLOUT))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK)
            {
                lwipOut = -1;
                errno = EAGAIN;
                break;
            }
            continue;
        }
        lwipOut = lwip_sendto(sock->lwip_fd, buff, len, flags, (void *)aligned, sizeof(struct sockaddr_in));
        if (lwipOut >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    sockaddrLwipToLinux(aligned, aligned, initialFamily);

    free(aligned);

    arch_disable_interrupt();

    if (lwipOut < 0)
        return -errno;
    return lwipOut;
}

size_t real_socket_recvfrom(uint64_t fd, uint8_t *buff, size_t len, int flags, struct sockaddr_un *addr, socklen_t *addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    if (!addrlen || !addr)
        return real_socket_recv(fd, buff, len, flags);

    arch_enable_interrupt();

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));

    int lwipOut = -1;
    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK)
            {
                lwipOut = -1;
                errno = EAGAIN;
                break;
            }
            continue;
        }
        lwipOut = lwip_recvfrom(sock->lwip_fd, buff, len, flags, (void *)a, addrlen);
        if (lwipOut >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    sockaddrLwipToLinux(addr, a, AF_INET);

    free(a);

    arch_disable_interrupt();

    if (lwipOut < 0)
        return -errno;

    *addrlen -= 1;

    return lwipOut;
}

int real_socket_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));

    uint16_t initial_family = sockaddrLinuxToLwip((void *)a, addr, addrlen);
    if (!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK))
        lwip_fcntl(sock->lwip_fd, F_SETFL, 0);
    int lwip_out = lwip_connect(sock->lwip_fd, (void *)a, sizeof(struct sockaddr_in));
    if (!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK))
        lwip_fcntl(sock->lwip_fd, F_SETFL, O_NONBLOCK);
    sockaddrLwipToLinux((void *)addr, a, initial_family);
    free(a);
    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

int real_socket_getsockname(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    int lwip_out = lwip_getsockname(sock->lwip_fd, (void *)a, addrlen);
    sockaddrLwipToLinux(addr, a, AF_INET);
    free(a);
    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = lwip_getsockopt(sock->lwip_fd, level, optname, optval, optlen);
    if (lwip_out < 0)
        return -errno;
    return lwip_out;
}

size_t real_socket_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = lwip_setsockopt(sock->lwip_fd, level, optname, optval, optlen);
    if (lwip_out < 0)
        return -errno;
    return lwip_out;
}

size_t real_socket_sendmsg(uint64_t fd, const struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    struct msghdr mh = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = msg->msg_iov,
        .msg_iovlen = msg->msg_iovlen,
        .msg_control = msg->msg_control,
        .msg_controllen = msg->msg_controllen,
        .msg_flags = msg->msg_flags,
    };

    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLOUT) & EPOLLOUT))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK || flags & 0x40)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_sendmsg(sock->lwip_fd, &mh, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

size_t real_socket_recvmsg(uint64_t fd, struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));

    struct msghdr mh = {
        .msg_name = a,
        .msg_namelen = sizeof(struct sockaddr_in),
        .msg_iov = msg->msg_iov,
        .msg_iovlen = msg->msg_iovlen,
        .msg_control = msg->msg_control,
        .msg_controllen = msg->msg_controllen,
        .msg_flags = msg->msg_flags,
    };

    while (true)
    {
        if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN))
        {
            if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK || flags & 0x40)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_recvmsg(sock->lwip_fd, &mh, flags);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    if (msg->msg_name)
    {
        sockaddrLwipToLinux(msg->msg_name, a, 2);
        msg->msg_namelen = sizeof(struct sockaddr_in);
    }

    return lwip_out;
}

int real_socket_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    sockaddrLinuxToLwip(a, addr, addrlen);
    int out = lwip_bind(sock->lwip_fd, (const struct sockaddr *)a, sizeof(struct sockaddr_in));
    free(a);
    if (out < 0)
        return -errno;

    return out;
}

int real_socket_listen(uint64_t fd, int backlog)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_t *sock = handle->sock;

    int out = lwip_listen(sock->lwip_fd, backlog);
    if (out < 0)
        return -errno;

    return out;
}

int real_socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags)
{
    // socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    // real_socket_t *sock = handle->sock;

    // uint32_t revents = 0;

    // do
    // {
    //     struct pollfd single = {.revents = 0,
    //                             .events = epoll_to_poll_comp(EPOLLIN),
    //                             .fd = sock->lwip_fd};

    //     int ret = lwip_poll(&single, 1, 0);
    //     if (ret != 1)
    //         return -errno;

    //     revents = poll_to_epoll_comp(single.revents);
    // } while (!(revents & EPOLLIN));

    // struct sockaddr_in *a = malloc(sizeof(struct sockaddr_in));
    // sockaddrLinuxToLwip(a, addr, 0);
    // int new_lwip_fd = lwip_accept(sock->lwip_fd, a, addrlen);
    // free(a);
    // if (new_lwip_fd < 0)
    //     return -errno;

    // *addrlen -= 1;

    // vfs_node_t socknode = vfs_node_alloc(NULL, "realsock");
    // socknode->type = file_socket;
    // socknode->fsid = realsock_fsid;
    // socknode->refcount++;
    // socket_handle_t *new_handle = malloc(sizeof(socket_handle_t));
    // memset(new_handle, 0, sizeof(socket_handle_t));
    // real_socket_t *real_socket = malloc(sizeof(real_socket_t));
    // memset(real_socket, 0, sizeof(real_socket_t));

    // new_handle->sock = real_socket;
    // real_socket->lwip_fd = new_lwip_fd;
    // new_handle->op = &real_socket_ops;
    // socknode->handle = new_handle;

    // uint64_t i = 0;
    // for (i = 3; i < MAX_FD_NUM; i++)
    // {
    //     if (current_task->fd_info->fds[i] == NULL)
    //     {
    //         break;
    //     }
    // }

    // if (i == MAX_FD_NUM)
    // {
    //     return -EMFILE;
    // }

    // current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    // current_task->fd_info->fds[i]->node = socknode;
    // current_task->fd_info->fds[i]->offset = 0;
    // current_task->fd_info->fds[i]->flags = 0;

    // new_handle->fd = current_task->fd_info->fds[i];

    // return i;

    return -ENOSYS;
}

socket_op_t real_socket_ops = {
    .getsockname = real_socket_getsockname,
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

bool real_socket_close(void *current)
{
    socket_handle_t *handle = (socket_handle_t *)current;
    real_socket_t *sock = handle->sock;

    lwip_close(sock->lwip_fd);

    return true;
}

int real_socket_poll(void *curr, size_t events)
{
    socket_handle_t *handle = (socket_handle_t *)curr;
    real_socket_t *sock = handle->sock;

    struct pollfd single = {.revents = 0,
                            .events = epoll_to_poll_comp(events),
                            .fd = sock->lwip_fd};

    int ret = lwip_poll(&single, 1, 0);
    if (ret != 1)
        return 0;

    return poll_to_epoll_comp(single.revents);
}

ssize_t real_socket_read(fd_t *fd, void *addr, size_t offset, size_t size)
{
    socket_handle_t *handle = fd->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    while (true)
    {
        if (!(vfs_poll(fd->node, EPOLLIN) & EPOLLIN))
        {
            if (fd->flags & O_NONBLOCK)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_read(sock->lwip_fd, addr, size);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

ssize_t real_socket_write(fd_t *fd, const void *addr, size_t offset, size_t size)
{
    socket_handle_t *handle = fd->node->handle;
    real_socket_t *sock = handle->sock;

    int lwip_out = -1;

    arch_enable_interrupt();

    while (true)
    {
        if (!(vfs_poll(fd->node, EPOLLOUT) & EPOLLOUT))
        {
            if (fd->flags & O_NONBLOCK)
            {
                lwip_out = -1;
                errno = EAGAIN;
                break;
            }
        }

        lwip_out = lwip_write(sock->lwip_fd, addr, size);
        if (lwip_out >= 0 || errno != EAGAIN)
            break;

        arch_yield();
    }

    arch_disable_interrupt();

    if (lwip_out < 0)
        return -errno;

    return lwip_out;
}

static int dummy()
{
    return 0;
}

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)real_socket_close,
    .read = (vfs_read_t)real_socket_read,
    .write = (vfs_write_t)real_socket_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)real_socket_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)vfs_generic_dup,
};

bool real_socket_initialized = false;

static void delay(uint64_t ms)
{
    uint64_t ns = ms * 1000000;
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns)
    {
        arch_yield();
    }
}

void receiver_entry(uint64_t arg)
{
    uint32_t mtu = ((netdev_t *)arg)->mtu;
    char *buf = malloc(mtu);
    memset(buf, 0, mtu);

    while (1)
    {
        int len = netdev_recv((netdev_t *)arg, buf, mtu);
        if (len > 0)
        {
            struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
            pbuf_take(p, buf, len);
            global_netif.input(p, &global_netif);
            memset(buf, 0, mtu);
        }
        delay(100);
    }
}

err_t lwip_dummy_init(struct netif *netif)
{
    return ERR_OK;
}

err_t lwip_output(struct netif *netif, struct pbuf *p)
{
    uint8_t *complete = malloc(p->tot_len);

    pbuf_copy_partial(p, complete, p->tot_len, 0);

    netdev_send(get_default_netdev(), complete, p->tot_len);

    free(complete);

    return ERR_OK;
}

void lwip_init_in_thread(void *nicPre)
{
    netdev_t *nic = (netdev_t *)nicPre;
    // struct ethernetif *ethernetif;

    struct netif *this_netif = &global_netif;

    this_netif->state = NULL;
    this_netif->name[0] = 65;
    this_netif->name[1] = 66;
    this_netif->next = NULL;

    netif_add(this_netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL, lwip_dummy_init, tcpip_input); // ethernetif_init_low

    this_netif->output = etharp_output;
    this_netif->linkoutput = lwip_output;
    this_netif->hwaddr_len = ETHARP_HWADDR_LEN;
    this_netif->hwaddr[0] = nic->mac[0]; // or whatever u like
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

    if (out != ERR_OK)
    {
        printk("Failed to start DHCP\n");
        task_exit(0);
    }

    delay(1000);

    sys_check_timeouts();
    dhcp_supplied_address(this_netif);
}

void real_socket_init_global_netif()
{
    if (get_default_netdev())
    {
        task_create("net_receiver", receiver_entry, (uint64_t)get_default_netdev(), KTHREAD_PRIORITY);
        tcpip_init(lwip_init_in_thread, get_default_netdev());
    }
}

int real_socket_socket(int domain, int type, int protocol)
{
    if (!real_socket_initialized)
    {
        real_socket_init_global_netif();
        real_socket_initialized = true;
    }

    int try_bound = 0;
    while (!dhcp_supplied_address(&global_netif))
    {
        try_bound++;
        if (try_bound >= 10)
            return -EHOSTUNREACH;
        sys_check_timeouts();
        delay(1000);
    }

    int lwip_fd = lwip_socket(domain, type, protocol);
    if (lwip_fd < 0)
        return -errno;

    vfs_node_t socknode = vfs_node_alloc(NULL, "realsock");
    socknode->type = file_socket;
    socknode->fsid = realsock_fsid;
    socknode->refcount++;
    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    real_socket_t *real_socket = malloc(sizeof(real_socket_t));
    memset(real_socket, 0, sizeof(real_socket_t));

    handle->sock = real_socket;
    real_socket->lwip_fd = lwip_fd;
    handle->op = &real_socket_ops;
    socknode->handle = handle;

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++)
    {
        if (current_task->fd_info->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return -EMFILE;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = socknode;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = 0;

    handle->fd = current_task->fd_info->fds[i];

    return i;
}

void real_socket_init()
{
    realsock_fsid = vfs_regist("realsock", &callbacks);

    regist_socket(2, real_socket_socket);
}
