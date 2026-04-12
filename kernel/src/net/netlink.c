#include <net/netlink.h>
#include <net/rtnl.h>
#include <task/task.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <libs/klibc.h>
#include <fs/fs_syscall.h>
#include <fs/proc.h>
#include <net/real_socket.h>
#include <bpf/socket_filter.h>
#include <init/callbacks.h>

// Global netlink socket tracking
#define MAX_NETLINK_SOCKETS 256
static struct netlink_sock *netlink_sockets[MAX_NETLINK_SOCKETS] = {0};
static spinlock_t netlink_sockets_lock = SPIN_INIT;

#define MAX_NETLINK_MSG_POOL_SIZE 1024

struct netlink_msg_pool_entry {
    char message[NETLINK_BUFFER_SIZE];
    size_t length;
    uint64_t timestamp;
    uint32_t seqnum;    // For uevent, 0 for others
    char devpath[256];  // For uevent, empty for others
    uint32_t nl_pid;    // Sender's port ID
    uint32_t nl_groups; // Target groups (bitmask)
    int protocol;       // Netlink protocol (NETLINK_KOBJECT_UEVENT, etc.)
    bool valid;
};

static struct netlink_msg_pool_entry
    netlink_msg_pool[MAX_NETLINK_MSG_POOL_SIZE];
static uint32_t netlink_msg_pool_next = 0;
static spinlock_t netlink_msg_pool_lock = SPIN_INIT;

static void netlink_handle_release(socket_handle_t *handle);
static ssize_t netlink_read_op(fd_t *fd, void *buf, size_t offset,
                               size_t count);
static ssize_t netlink_write_op(fd_t *fd, const void *buf, size_t offset,
                                size_t count);
int netlink_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg);
int netlink_poll(vfs_node_t *node, size_t events);

// Function to add message to persistent pool
static void netlink_msg_pool_add(const char *message, size_t length,
                                 uint32_t nl_pid, uint32_t nl_groups,
                                 int protocol, uint32_t seqnum,
                                 const char *devpath) {
    if (message == NULL || length == 0 || nl_groups == 0) {
        return;
    }

    spin_lock(&netlink_msg_pool_lock);

    struct netlink_msg_pool_entry *entry =
        &netlink_msg_pool[netlink_msg_pool_next];
    entry->valid = true;
    entry->length =
        (length < NETLINK_BUFFER_SIZE) ? length : NETLINK_BUFFER_SIZE - 1;
    memcpy(entry->message, message, entry->length);
    entry->message[entry->length] = '\0';
    entry->timestamp = 0; // TODO: Get current time
    entry->nl_pid = nl_pid;
    entry->nl_groups = nl_groups;
    entry->protocol = protocol;
    entry->seqnum = seqnum;

    if (devpath) {
        strncpy(entry->devpath, devpath, sizeof(entry->devpath) - 1);
        entry->devpath[sizeof(entry->devpath) - 1] = '\0';
    } else {
        entry->devpath[0] = '\0';
    }

    netlink_msg_pool_next =
        (netlink_msg_pool_next + 1) % MAX_NETLINK_MSG_POOL_SIZE;

    spin_unlock(&netlink_msg_pool_lock);
}

// Function to retrieve message from pool by seqnum (for uevent)
static bool netlink_msg_pool_get_by_seqnum(uint32_t seqnum, char *buffer,
                                           size_t *length, uint32_t *nl_pid,
                                           uint32_t *nl_groups) {
    spin_lock(&netlink_msg_pool_lock);
    bool found = false;

    for (int i = 0; i < MAX_NETLINK_MSG_POOL_SIZE; i++) {
        struct netlink_msg_pool_entry *entry = &netlink_msg_pool[i];
        if (entry->valid && entry->seqnum == seqnum) {
            size_t copy_len =
                (entry->length < *length) ? entry->length : *length;
            memcpy(buffer, entry->message, copy_len);
            *length = copy_len;
            if (nl_pid)
                *nl_pid = entry->nl_pid;
            if (nl_groups)
                *nl_groups = entry->nl_groups;
            found = true;
            break;
        }
    }

    spin_unlock(&netlink_msg_pool_lock);
    return found;
}

// Function to retrieve message from pool by devpath (for uevent)
static bool netlink_msg_pool_get_by_devpath(const char *devpath, char *buffer,
                                            size_t *length, uint32_t *nl_pid,
                                            uint32_t *nl_groups) {
    spin_lock(&netlink_msg_pool_lock);
    bool found = false;

    for (int i = 0; i < MAX_NETLINK_MSG_POOL_SIZE; i++) {
        struct netlink_msg_pool_entry *entry = &netlink_msg_pool[i];
        if (entry->valid && strcmp(entry->devpath, devpath) == 0) {
            size_t copy_len =
                (entry->length < *length) ? entry->length : *length;
            memcpy(buffer, entry->message, copy_len);
            *length = copy_len;
            if (nl_pid)
                *nl_pid = entry->nl_pid;
            if (nl_groups)
                *nl_groups = entry->nl_groups;
            found = true;
            break;
        }
    }

    spin_unlock(&netlink_msg_pool_lock);
    return found;
}

static void netlink_packet_meta_destroy(void *priv) { free(priv); }

static skb_buff_t *netlink_packet_build_skb(const char *data, size_t len,
                                            uint32_t nl_pid,
                                            uint32_t nl_groups) {
    skb_buff_t *skb = NULL;
    struct netlink_packet_hdr *hdr = NULL;

    skb = skb_alloc(len);
    if (!skb)
        return NULL;

    hdr = malloc(sizeof(*hdr));
    if (!hdr) {
        skb_free(skb, NULL);
        return NULL;
    }

    if (len > 0)
        memcpy(skb->data, data, len);

    hdr->nl_pid = nl_pid;
    hdr->nl_groups = nl_groups;
    hdr->length = (uint32_t)len;
    skb->priv = hdr;
    return skb;
}

static void netlink_buffer_init(struct netlink_buffer *buf) {
    memset(buf, 0, sizeof(struct netlink_buffer));
    buf->size = NETLINK_BUFFER_SIZE;
    skb_queue_init(&buf->queue, NETLINK_BUFFER_SIZE,
                   netlink_packet_meta_destroy);
    buf->lock = SPIN_INIT;
}

static inline void netlink_notify_sock(struct netlink_sock *sock,
                                       uint32_t events) {
    if (!sock || !sock->node || !events)
        return;
    vfs_poll_notify(sock->node, events);
}

static bool netlink_group_mask_matches(uint32_t subscribed_groups,
                                       uint32_t target_groups) {
    return target_groups != 0 && (subscribed_groups & target_groups) != 0;
}

static bool netlink_portid_in_use_locked(const struct netlink_sock *self,
                                         uint32_t portid) {
    if (!portid)
        return true;

    for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
        struct netlink_sock *sock = netlink_sockets[i];
        if (!sock || sock == self)
            continue;
        if (sock->portid == portid)
            return true;
    }

    return false;
}

static uint32_t netlink_resolve_portid_locked(struct netlink_sock *self,
                                              uint32_t requested_portid) {
    if (requested_portid) {
        if (netlink_portid_in_use_locked(self, requested_portid))
            return 0;
        return requested_portid;
    }

    uint32_t candidate = (uint32_t)current_task->pid;
    if (!candidate)
        candidate = 1;

    while (netlink_portid_in_use_locked(self, candidate)) {
        candidate++;
        if (!candidate)
            candidate = 1;
    }

    return candidate;
}

static int netlink_wait_sock(struct netlink_sock *sock, uint32_t events,
                             const char *reason) {
    if (!sock || !sock->node || !current_task)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    int polled = vfs_poll(sock->node, want);
    if (polled < 0)
        return polled;
    if (polled & (int)want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(sock->node, &wait) < 0)
        return -EINVAL;
    polled = vfs_poll(sock->node, want);
    if (polled < 0) {
        vfs_poll_wait_disarm(&wait);
        return polled;
    }
    if (polled & (int)want) {
        vfs_poll_wait_disarm(&wait);
        return EOK;
    }
    int ret = vfs_poll_wait_sleep(sock->node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
}

// skb queue operations for netlink packets with sender info
size_t netlink_buffer_write_packet(struct netlink_sock *sock, const char *data,
                                   size_t len, uint32_t nl_pid,
                                   uint32_t nl_groups) {
    struct netlink_buffer *buf = sock->buffer;
    skb_buff_t *skb = NULL;
    size_t total_needed = 0;

    if (buf == NULL || data == NULL || len == 0) {
        return 0;
    }

    if (sock->filter) {
        uint32_t accept_bytes = bpf_run(sock->filter->filter, sock->filter->len,
                                        (const uint8_t *)data, (uint32_t)len);
        if (!accept_bytes)
            return 0;
        len = MIN(len, accept_bytes);
    }

    total_needed = sizeof(struct netlink_packet_hdr) + len;
    if (total_needed > buf->size - 1)
        return 0;

    skb = netlink_packet_build_skb(data, len, nl_pid, nl_groups);
    if (!skb)
        return 0;

    spin_lock(&buf->lock);
    if (buf->used_bytes + total_needed > buf->size - 1 ||
        !skb_queue_push(&buf->queue, skb)) {
        spin_unlock(&buf->lock);
        skb_free(skb, netlink_packet_meta_destroy);
        return 0;
    }

    buf->used_bytes += total_needed;
    spin_unlock(&buf->lock);
    netlink_notify_sock(sock, EPOLLIN);
    return len;
}

// Read data from buffer with sender info
static size_t netlink_buffer_read_packet(struct netlink_sock *sock, char *out,
                                         size_t out_len, uint32_t *nl_pid,
                                         uint32_t *nl_groups, bool peek) {
    struct netlink_buffer *buf = sock->buffer;
    skb_buff_t *skb = NULL;
    struct netlink_packet_hdr *hdr = NULL;
    size_t packet_len = 0;
    size_t copy_len = 0;

    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);
    skb = skb_queue_peek(&buf->queue);
    if (!skb) {
        spin_unlock(&buf->lock);
        return 0;
    }

    hdr = (struct netlink_packet_hdr *)skb->priv;
    packet_len = skb_unread_len(skb);

    if (nl_pid)
        *nl_pid = hdr ? hdr->nl_pid : 0;
    if (nl_groups)
        *nl_groups = hdr ? hdr->nl_groups : 0;

    if (out != NULL && out_len > 0) {
        copy_len = MIN(packet_len, out_len);
        skb_copy_data(skb, 0, out, copy_len);
    } else {
        copy_len = packet_len;
    }

    if (!peek) {
        skb_buff_t *done = skb_queue_pop(&buf->queue);
        if (done) {
            buf->used_bytes -= sizeof(struct netlink_packet_hdr) + done->len;
            skb_free(done, netlink_packet_meta_destroy);
        }
    }

    spin_unlock(&buf->lock);
    return copy_len;
}

// Check if a complete message is available
static bool netlink_buffer_has_msg(struct netlink_sock *sock) {
    struct netlink_buffer *buf = sock->buffer;
    bool has_complete_msg = false;

    if (buf == NULL) {
        return false;
    }

    spin_lock(&buf->lock);
    has_complete_msg = skb_queue_packets(&buf->queue) > 0;
    spin_unlock(&buf->lock);
    return has_complete_msg;
}

// Get the length of next message without consuming it
static size_t netlink_buffer_peek_msg_len(struct netlink_sock *sock) {
    struct netlink_buffer *buf = sock->buffer;
    skb_buff_t *skb = NULL;
    size_t msg_len = 0;

    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);
    skb = skb_queue_peek(&buf->queue);
    if (skb)
        msg_len = skb_unread_len(skb);
    spin_unlock(&buf->lock);
    return msg_len;
}

static size_t netlink_buffer_available(struct netlink_buffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);
    size_t avail = buf->used_bytes;
    spin_unlock(&buf->lock);
    return avail;
}

static void netlink_deliver_historical_messages(struct netlink_sock *sock) {
    int start = 0;

    if (sock == NULL || sock->buffer == NULL || sock->groups == 0) {
        return;
    }

    spin_lock(&netlink_msg_pool_lock);
    start = netlink_msg_pool_next;
    spin_unlock(&netlink_msg_pool_lock);

    for (int count = 0; count < MAX_NETLINK_MSG_POOL_SIZE; count++) {
        char message[NETLINK_BUFFER_SIZE];
        size_t length = 0;
        uint32_t nl_pid = 0;
        uint32_t nl_groups = 0;
        int protocol = 0;
        bool should_deliver = false;

        spin_lock(&netlink_msg_pool_lock);
        struct netlink_msg_pool_entry *entry =
            &netlink_msg_pool[(start + count) % MAX_NETLINK_MSG_POOL_SIZE];

        if (entry->valid) {
            protocol = entry->protocol;
            nl_groups = entry->nl_groups;
            if (protocol == sock->protocol &&
                netlink_group_mask_matches(sock->groups, nl_groups)) {
                length = entry->length;
                nl_pid = entry->nl_pid;
                memcpy(message, entry->message, length);
                should_deliver = true;
            }
        }
        spin_unlock(&netlink_msg_pool_lock);

        if (!should_deliver)
            continue;

        if (netlink_buffer_write_packet(sock, message, length, nl_pid,
                                        nl_groups) == 0) {
            break;
        }
    }
}

// 内部发送函数，用于向指定 socket 发送消息
static size_t netlink_deliver_to_socket(struct netlink_sock *target,
                                        const char *data, size_t len,
                                        uint32_t sender_pid,
                                        uint32_t sender_groups) {
    if (target == NULL || target->buffer == NULL) {
        return 0;
    }

    return netlink_buffer_write_packet(target, data, len, sender_pid,
                                       sender_groups);
}

// Broadcast message to all listening netlink sockets and save to pool
void netlink_broadcast_to_group(const char *buf, size_t len,
                                uint32_t sender_pid, uint32_t target_groups,
                                int protocol, uint32_t seqnum,
                                const char *devpath) {
    if (buf == NULL || len == 0) {
        return;
    }

    // Add to persistent pool
    netlink_msg_pool_add(buf, len, sender_pid, target_groups, protocol, seqnum,
                         devpath);

    // Broadcast to all sockets subscribed to matching groups
    spin_lock(&netlink_sockets_lock);

    for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
        if (netlink_sockets[i] == NULL)
            continue;

        struct netlink_sock *sock = netlink_sockets[i];

        // 检查 protocol 是否匹配
        if (sock->protocol != protocol)
            continue;

        spin_lock(&sock->lock);

        if (netlink_group_mask_matches(sock->groups, target_groups)) {
            netlink_buffer_write_packet(sock, buf, len, sender_pid,
                                        target_groups);
        }

        spin_unlock(&sock->lock);
    }

    spin_unlock(&netlink_sockets_lock);
}

int netlink_bind(uint64_t fd, const struct sockaddr_un *addr,
                 socklen_t addrlen) {
    if (addr == NULL || addrlen < sizeof(struct sockaddr_nl)) {
        return -EINVAL;
    }

    if (current_task->fd_info->fds[fd] == NULL ||
        current_task->fd_info->fds[fd]->node == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    if (handle == NULL || handle->sock == NULL) {
        return -EBADF;
    }

    struct netlink_sock *sock = handle->sock;
    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;

    if (nl_addr->nl_family != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }

    spin_lock(&netlink_sockets_lock);
    uint32_t portid = netlink_resolve_portid_locked(sock, nl_addr->nl_pid);
    if (!portid) {
        spin_unlock(&netlink_sockets_lock);
        return -EADDRINUSE;
    }

    spin_lock(&sock->lock);
    sock->portid = portid;
    sock->groups = nl_addr->nl_groups;

    if (sock->bind_addr == NULL) {
        sock->bind_addr = malloc(sizeof(struct sockaddr_nl));
        if (sock->bind_addr == NULL) {
            spin_unlock(&sock->lock);
            spin_unlock(&netlink_sockets_lock);
            return -ENOMEM;
        }
    }
    memcpy(sock->bind_addr, nl_addr, sizeof(struct sockaddr_nl));
    sock->bind_addr->nl_pid = sock->portid;
    spin_unlock(&sock->lock);
    spin_unlock(&netlink_sockets_lock);

    netlink_deliver_historical_messages(sock);

    return 0;
}

size_t netlink_getsockopt(uint64_t fd, int level, int optname, void *optval,
                          socklen_t *optlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_TYPE:
            *(int *)optval = nl_sk->type;
            *optlen = sizeof(int);
            break;
        case SO_PROTOCOL:
            *(int *)optval = nl_sk->protocol;
            *optlen = sizeof(int);
            break;
        case SO_REUSEADDR:
            break;
        case SO_PASSCRED:
            break;
        case SO_SNDBUF:
        case SO_SNDBUFFORCE:
        case SO_RCVBUF:
        case SO_RCVBUFFORCE:
            break;
        default:
            printk("%s:%d Unsupported optlevel or optname %d %d\n", __FILE__,
                   __LINE__, level, optname);
            return -ENOPROTOOPT;
        }
    } else if (level == SOL_NETLINK) {
        return 0;
    } else {
        printk("%s:%d Unsupported optlevel or optname %d %d\n", __FILE__,
               __LINE__, level, optname);
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t netlink_setsockopt(uint64_t fd, int level, int optname,
                          const void *optval, socklen_t optlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_ATTACH_FILTER:
            const struct sock_fprog *fprog = optval;
            if (!fprog->len) {
                return (size_t)-EINVAL;
            }
            nl_sk->filter = malloc(sizeof(struct sock_fprog));
            nl_sk->filter->len = fprog->len;
            nl_sk->filter->filter =
                malloc(nl_sk->filter->len * sizeof(struct sock_filter));
            memset(nl_sk->filter->filter, 0,
                   nl_sk->filter->len * sizeof(struct sock_filter));
            if (copy_from_user(nl_sk->filter->filter, fprog->filter,
                               nl_sk->filter->len *
                                   sizeof(struct sock_filter))) {
                free(nl_sk->filter->filter);
                free(nl_sk->filter);
                return (size_t)-EFAULT;
            }
            break;
        case SO_DETACH_FILTER:
            if (nl_sk->filter) {
                free(nl_sk->filter->filter);
                free(nl_sk->filter);
                nl_sk->filter = NULL;
            }
            break;
        case SO_REUSEADDR:
            break;
        case SO_PASSCRED:
            break;
        case SO_SNDBUF:
        case SO_SNDBUFFORCE:
        case SO_RCVBUF:
        case SO_RCVBUFFORCE:
            break;
        default:
            printk("%s:%d Unsupported optlevel or optname %d %d\n", __FILE__,
                   __LINE__, level, optname);
            return -ENOPROTOOPT;
        }
    } else if (level == SOL_NETLINK) {
        switch (optname) {
        case NETLINK_ADD_MEMBERSHIP:
        case NETLINK_DROP_MEMBERSHIP: {
            if (!optval || optlen < sizeof(uint32_t))
                return -EINVAL;

            uint32_t group = *(const uint32_t *)optval;
            if (group == 0 || group > 32)
                return -EINVAL;

            uint32_t bit = 1U << (group - 1);
            spin_lock(&nl_sk->lock);
            if (optname == NETLINK_ADD_MEMBERSHIP)
                nl_sk->groups |= bit;
            else
                nl_sk->groups &= ~bit;
            if (nl_sk->bind_addr)
                nl_sk->bind_addr->nl_groups = nl_sk->groups;
            spin_unlock(&nl_sk->lock);
            return 0;
        }
        default:
            printk("%s:%d Unsupported optlevel or optname %d %d\n", __FILE__,
                   __LINE__, level, optname);
            return -ENOPROTOOPT;
        }
    } else {
        printk("%s:%d Unsupported optlevel or optname %d %d\n", __FILE__,
               __LINE__, level, optname);
        return -ENOPROTOOPT;
    }

    return 0;
}

int netlink_getsockname(uint64_t fd, struct sockaddr_un *addr,
                        socklen_t *addrlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    spin_lock(&nl_sk->lock);

    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = nl_sk->portid;
    nl_addr->nl_groups = nl_sk->groups;
    nl_addr->nl_pad = 0;

    *addrlen = sizeof(struct sockaddr_nl);

    spin_unlock(&nl_sk->lock);
    return 0;
}

size_t netlink_recvmsg(uint64_t fd, struct msghdr *msg, int flags) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->buffer == NULL) {
        return -EINVAL;
    }

    bool peek = !!(flags & MSG_PEEK);
    bool noblock =
        !!(flags & MSG_DONTWAIT) ||
        !!(fd_get_flags(current_task->fd_info->fds[fd]) & O_NONBLOCK);

    msg->msg_flags = 0;

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    while (!has_msg) {
        int reason = netlink_wait_sock(nl_sk, EPOLLIN, "netlink_recvmsg");
        if (reason != EOK)
            return -EINTR;
        has_msg = netlink_buffer_has_msg(nl_sk);
    }

    // 计算用户缓冲区总大小
    size_t total_user_len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
        total_user_len += msg->msg_iov[i].len;
    }

    char temp_buf[NETLINK_BUFFER_SIZE];
    uint32_t sender_pid = 0;
    uint32_t sender_groups = 0;

    // Read the complete message into a temporary buffer with sender info
    size_t bytes_read = netlink_buffer_read_packet(
        nl_sk, temp_buf, sizeof(temp_buf), &sender_pid, &sender_groups, peek);
    if (bytes_read == 0) {
        return -EAGAIN;
    }

    // Copy the message to user iovec(s)
    size_t total_copied = 0;
    size_t remaining = bytes_read;
    char *src = temp_buf;

    for (int i = 0; i < msg->msg_iovlen && remaining > 0; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        size_t to_copy = (remaining < curr->len) ? remaining : curr->len;

        if (to_copy > 0) {
            memcpy(curr->iov_base, src, to_copy);
            src += to_copy;
            remaining -= to_copy;
            total_copied += to_copy;
        }
    }

    // 如果设置了 MSG_TRUNC，返回原始消息长度
    size_t ret_len = (flags & MSG_TRUNC) ? bytes_read : total_copied;

    // Fill in ancillary data if requested
    if (msg->msg_control && msg->msg_controllen > 0) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
        if (cmsg && msg->msg_controllen >= CMSG_LEN(sizeof(struct ucred))) {
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_CREDENTIALS;

            struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
            cred->pid = sender_pid;
            cred->gid = 0;
            cred->uid = 0;

            msg->msg_controllen = cmsg->cmsg_len;
        } else {
            msg->msg_controllen = 0;
        }
    }

    // Fill in socket address if requested
    if (msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)msg->msg_name;
        nl_addr->nl_family = AF_NETLINK;
        nl_addr->nl_pid = sender_pid;
        nl_addr->nl_groups = sender_groups;
        nl_addr->nl_pad = 0;
        msg->msg_namelen = sizeof(struct sockaddr_nl);
    }

    // 设置 MSG_TRUNC 标志如果消息被截断
    if (remaining > 0) {
        msg->msg_flags |= MSG_TRUNC;
    }

    return ret_len;
}

size_t netlink_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    // Calculate total message length
    size_t total_len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].len;
    }

    if (total_len == 0) {
        return 0;
    }

    if (total_len > NETLINK_BUFFER_SIZE - sizeof(struct netlink_packet_hdr)) {
        return -EMSGSIZE;
    }

    // Copy data into buffer
    char buffer[NETLINK_BUFFER_SIZE];
    size_t offset = 0;

    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        if (curr->iov_base && curr->len > 0) {
            memcpy(buffer + offset, curr->iov_base, curr->len);
            offset += curr->len;
        }
    }

    // Get sender's pid and groups
    uint32_t sender_pid = nl_sk->portid;
    uint32_t sender_groups = nl_sk->groups;

    struct sockaddr_nl *addr = (struct sockaddr_nl *)msg->msg_name;
    if (!addr)
        return 0;

    if (addr->nl_pid != 0) {
        // Unicast to specific pid - 不保存到 pool
        spin_lock(&netlink_sockets_lock);
        for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
            if (netlink_sockets[i] == NULL)
                continue;

            struct netlink_sock *sock = netlink_sockets[i];
            if (sock->portid == addr->nl_pid) {
                spin_lock(&sock->lock);
                netlink_deliver_to_socket(sock, buffer, total_len, sender_pid,
                                          sender_groups);
                spin_unlock(&sock->lock);
                break;
            }
        }
        spin_unlock(&netlink_sockets_lock);

        // Unicast 如果目标不存在，静默成功（类似 UDP 行为）
    } else if (addr->nl_groups != 0) {
        // Multicast to groups - 保存到 pool 并广播
        netlink_broadcast_to_group(buffer, total_len, sender_pid,
                                   addr->nl_groups, nl_sk->protocol, 0, NULL);
    } else {
        // nl_pid == 0 && nl_groups == 0, sending to kernel
        if (nl_sk->protocol == NETLINK_ROUTE) {
            // Route to RTNL subsystem for processing
            rtnl_process_msg(nl_sk, buffer, total_len, sender_pid);
        }
        return total_len;
    }

    return total_len;
}

size_t netlink_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags,
                      struct sockaddr_un *addr, uint32_t len) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (limit == 0) {
        return 0;
    }

    if (limit > NETLINK_BUFFER_SIZE - sizeof(struct netlink_packet_hdr)) {
        return -EMSGSIZE;
    }

    uint32_t sender_pid = nl_sk->portid;
    uint32_t sender_groups = nl_sk->groups;

    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;

    if (nl_addr == NULL) {
        return -EDESTADDRREQ;
    }

    if (nl_addr->nl_family != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }

    if (nl_addr->nl_pid == 0 && nl_addr->nl_groups == 0) {
        if (nl_sk->protocol == NETLINK_ROUTE) {
            rtnl_process_msg(nl_sk, (char *)in, limit, sender_pid);
        }
        return limit;
    }
    if (nl_addr->nl_pid != 0) {
        // Unicast - 不保存到 pool
        spin_lock(&netlink_sockets_lock);
        for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
            if (netlink_sockets[i] == NULL)
                continue;

            struct netlink_sock *sock = netlink_sockets[i];
            if (sock->portid == nl_addr->nl_pid) {
                spin_lock(&sock->lock);
                netlink_deliver_to_socket(sock, (char *)in, limit, sender_pid,
                                          sender_groups);
                spin_unlock(&sock->lock);
                break;
            }
        }
        spin_unlock(&netlink_sockets_lock);
    } else if (nl_addr->nl_groups != 0) {
        // Multicast to groups - 保存到 pool 并广播
        netlink_broadcast_to_group((char *)in, limit, sender_pid,
                                   nl_addr->nl_groups, nl_sk->protocol, 0,
                                   NULL);
    }

    return limit;
}

size_t netlink_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags,
                        struct sockaddr_un *addr, uint32_t *len) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->buffer == NULL) {
        return -EINVAL;
    }

    bool noblock =
        !!(flags & MSG_DONTWAIT) ||
        !!(fd_get_flags(current_task->fd_info->fds[fd]) & O_NONBLOCK);

    bool peek = !!(flags & MSG_PEEK);
    size_t msg_len = netlink_buffer_peek_msg_len(nl_sk);

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    while (!has_msg) {
        int reason = netlink_wait_sock(nl_sk, EPOLLIN, "netlink_recvfrom");
        if (reason != EOK)
            return -EINTR;
        has_msg = netlink_buffer_has_msg(nl_sk);
    }

    uint32_t sender_pid = 0;
    uint32_t sender_groups = 0;

    // 重新获取消息长度（用于 MSG_TRUNC）
    msg_len = netlink_buffer_peek_msg_len(nl_sk);

    // Read the complete message directly into the user buffer
    size_t bytes_read = netlink_buffer_read_packet(
        nl_sk, (char *)out, limit, &sender_pid, &sender_groups, peek);
    if (bytes_read == 0) {
        return -EAGAIN;
    }

    // Fill in socket address if requested
    if (addr) {
        struct sockaddr_nl nl_addr_out;
        nl_addr_out.nl_family = AF_NETLINK;
        nl_addr_out.nl_pid = sender_pid;
        nl_addr_out.nl_groups = sender_groups;
        nl_addr_out.nl_pad = 0;

        memcpy(addr, &nl_addr_out, sizeof(struct sockaddr_nl));
    }

    if (len) {
        uint32_t addr_len = sizeof(struct sockaddr_nl);
        memcpy(len, &addr_len, sizeof(uint32_t));
    }

    // 如果设置了 MSG_TRUNC，返回原始消息长度
    return (flags & MSG_TRUNC) ? msg_len : bytes_read;
}

socket_op_t netlink_ops = {
    .bind = netlink_bind,
    .getsockopt = netlink_getsockopt,
    .setsockopt = netlink_setsockopt,
    .getsockname = netlink_getsockname,
    .sendto = netlink_sendto,
    .recvfrom = netlink_recvfrom,
    .recvmsg = netlink_recvmsg,
    .sendmsg = netlink_sendmsg,
};

int netlink_socket(int domain, int type, int protocol) {
    if (domain != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }

    struct netlink_sock *nl_sk = malloc(sizeof(struct netlink_sock));
    if (nl_sk == NULL) {
        return -ENOMEM;
    }
    memset(nl_sk, 0, sizeof(struct netlink_sock));

    nl_sk->domain = domain;
    nl_sk->type = type & 0xF;
    nl_sk->protocol = protocol;
    nl_sk->portid = (uint32_t)current_task->pid;
    nl_sk->groups = 0;
    nl_sk->node = NULL;
    nl_sk->bind_addr = NULL;
    nl_sk->lock = SPIN_INIT;

    // Initialize buffer structure
    nl_sk->buffer = malloc(sizeof(struct netlink_buffer));
    if (nl_sk->buffer == NULL) {
        free(nl_sk);
        return -ENOMEM;
    }
    netlink_buffer_init(nl_sk->buffer);

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    if (handle == NULL) {
        free(nl_sk->buffer);
        free(nl_sk);
        return -ENOMEM;
    }
    memset(handle, 0, sizeof(socket_handle_t));

    handle->op = &netlink_ops;
    handle->sock = nl_sk;
    handle->read_op = netlink_read_op;
    handle->write_op = netlink_write_op;
    handle->ioctl_op = netlink_ioctl;
    handle->poll_op = netlink_poll;
    handle->release = netlink_handle_release;

    // Add to global socket array
    spin_lock(&netlink_sockets_lock);
    int slot = -1;
    for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
        if (netlink_sockets[i] == NULL) {
            netlink_sockets[i] = nl_sk;
            slot = i;
            break;
        }
    }
    spin_unlock(&netlink_sockets_lock);

    if (slot == -1) {
        // No available slot
        free(nl_sk->buffer);
        free(nl_sk);
        free(handle);
        return -ENOMEM;
    }

    uint64_t flags = 0;
    if (type & O_NONBLOCK) {
        flags |= O_NONBLOCK;
    }

    struct vfs_file *file = NULL;
    int ret = sockfs_create_handle_file(handle, flags, &file);
    if (ret < 0) {
        spin_lock(&netlink_sockets_lock);
        netlink_sockets[slot] = NULL;
        spin_unlock(&netlink_sockets_lock);
        free(handle);
        free(nl_sk->buffer);
        free(nl_sk);
        return ret;
    }

    nl_sk->node = file->f_inode;
    ret = task_install_file(current_task, file,
                            (type & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(file);

    if (ret < 0) {
        spin_lock(&netlink_sockets_lock);
        netlink_sockets[slot] = NULL;
        spin_unlock(&netlink_sockets_lock);
        return ret;
    }

    return ret;
}

int netlink_socket_pair(int type, int protocol, int *sv) {
    // Netlink doesn't support socketpair
    return -EOPNOTSUPP;
}

int netlink_poll(vfs_node_t *node, size_t events) {
    socket_handle_t *handle = sockfs_inode_socket_handle(node);
    if (handle == NULL || handle->sock == NULL) {
        return EPOLLERR;
    }

    struct netlink_sock *nl_sk = handle->sock;

    int revents = 0;

    if (events & EPOLLIN) {
        bool has_msg = netlink_buffer_has_msg(nl_sk);
        if (has_msg) {
            revents |= EPOLLIN;
        }
    }

    if (events & EPOLLOUT) {
        revents |= EPOLLOUT;
    }

    return revents;
}

ssize_t netlink_read(uint64_t fd, char *buf, size_t count) {
    return netlink_recvfrom(fd, (uint8_t *)buf, count, 0, NULL, NULL);
}

ssize_t netlink_write(uint64_t fd, const char *buf, size_t count) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->protocol == NETLINK_KOBJECT_UEVENT) {
        return count;
    }

    return -EDESTADDRREQ;
}

static ssize_t netlink_read_op(fd_t *fd, void *buf, size_t offset,
                               size_t count) {
    if (!fd || !fd->node || !sockfs_file_handle(fd))
        return -EBADF;

    socket_handle_t *handle = sockfs_file_handle(fd);
    struct netlink_sock *nl_sk = handle->sock;
    if (!nl_sk || !nl_sk->buffer)
        return -EINVAL;

    bool noblock = !!(fd_get_flags(fd) & O_NONBLOCK);
    bool has_msg = netlink_buffer_has_msg(nl_sk);
    if (!has_msg && noblock)
        return -EAGAIN;

    while (!has_msg) {
        int reason = netlink_wait_sock(nl_sk, EPOLLIN, "netlink_read");
        if (reason != EOK)
            return -EINTR;
        has_msg = netlink_buffer_has_msg(nl_sk);
    }

    uint32_t sender_pid = 0;
    uint32_t sender_groups = 0;
    size_t bytes = netlink_buffer_read_packet(
        nl_sk, (char *)buf, count, &sender_pid, &sender_groups, false);
    if (!bytes)
        return -EAGAIN;
    return (ssize_t)bytes;
}

static ssize_t netlink_write_op(fd_t *fd, const void *buf, size_t offset,
                                size_t count) {
    if (!fd || !fd->node || !sockfs_file_handle(fd))
        return -EBADF;

    socket_handle_t *handle = sockfs_file_handle(fd);
    struct netlink_sock *nl_sk = handle->sock;
    if (!nl_sk)
        return -EBADF;

    if (nl_sk->protocol == NETLINK_KOBJECT_UEVENT)
        return count;

    return -EDESTADDRREQ;
}

int netlink_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    socket_handle_t *handle = sockfs_file_handle(fd);
    struct netlink_sock *nl_sk = handle->sock;

    switch (cmd) {
    case FIONBIO:
        return 0;

    default:
        return -ENOTTY;
    }
}

static void netlink_handle_release(socket_handle_t *handle) {
    if (handle == NULL) {
        return;
    }

    struct netlink_sock *nl_sk = handle->sock;
    if (nl_sk != NULL) {
        nl_sk->node = NULL;
        // Remove from global socket array
        spin_lock(&netlink_sockets_lock);
        for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
            if (netlink_sockets[i] == nl_sk) {
                netlink_sockets[i] = NULL;
                break;
            }
        }
        spin_unlock(&netlink_sockets_lock);

        if (nl_sk->buffer != NULL) {
            skb_queue_purge(&nl_sk->buffer->queue);
            free(nl_sk->buffer);
        }
        if (nl_sk->bind_addr != NULL) {
            free(nl_sk->bind_addr);
        }
        free(nl_sk);
    }

    free(handle);
};

void netlink_init() {
    // Initialize message pool
    spin_lock(&netlink_msg_pool_lock);
    for (int i = 0; i < MAX_NETLINK_MSG_POOL_SIZE; i++) {
        netlink_msg_pool[i].valid = false;
    }
    netlink_msg_pool_next = 0;
    spin_unlock(&netlink_msg_pool_lock);

    regist_socket(16, NULL, netlink_socket, NULL);
}

static int atoi(const char *s) {
    int ans = 0;
    while (is_digit(*s)) {
        ans = ans * 10 + (*s) - '0';
        ++s;
    }
    return ans;
}

void netlink_uevent_resend_by_devpath(const char *devpath) {
    if (devpath == NULL || devpath[0] == '\0') {
        return;
    }

    char buffer[NETLINK_BUFFER_SIZE];
    size_t length = NETLINK_BUFFER_SIZE;
    uint32_t nl_pid = 0;
    uint32_t nl_groups = 0;

    if (netlink_msg_pool_get_by_devpath(devpath, buffer, &length, &nl_pid,
                                        &nl_groups)) {
        // Parse seqnum from the retrieved message
        uint32_t seqnum = 0;
        const char *ptr = buffer;
        while (*ptr) {
            if (strncmp(ptr, "SEQNUM=", 7) == 0) {
                seqnum = atoi(ptr + 7);
                break;
            }
            ptr += strlen(ptr) + 1;
        }

        // Re-broadcast to group
        netlink_broadcast_to_group(buffer, length, nl_pid, nl_groups,
                                   NETLINK_KOBJECT_UEVENT, seqnum, devpath);
    }
}

void netlink_kernel_uevent_send(const char *buf, int len) {
    if (buf == NULL || len <= 0 || len > NETLINK_BUFFER_SIZE) {
        return;
    }

    // Extract seqnum and devpath from uevent message
    uint32_t seqnum = 0;
    char devpath[256] = {0};

    // Parse the uevent message to extract SEQNUM and DEVPATH
    const char *ptr = buf;
    const char *end = buf + len;
    while (ptr < end && *ptr) {
        if (strncmp(ptr, "SEQNUM=", 7) == 0) {
            seqnum = atoi(ptr + 7);
        } else if (strncmp(ptr, "DEVPATH=", 8) == 0) {
            const char *val_end = strchr(ptr + 8, '\0');
            if (val_end) {
                size_t path_len = val_end - (ptr + 8);
                if (path_len < sizeof(devpath)) {
                    memcpy(devpath, ptr + 8, path_len);
                    devpath[path_len] = '\0';
                }
            }
        }
        ptr += strlen(ptr) + 1;
    }

    // Kernel sends with pid=0 and groups=1 (uevent group)
    // This will save to pool and broadcast to existing sockets
    netlink_broadcast_to_group(buf, len, 0, 1, NETLINK_KOBJECT_UEVENT, seqnum,
                               devpath);
}
