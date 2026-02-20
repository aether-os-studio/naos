#include <net/netlink.h>
#include <net/rtnl.h>
#include <task/task.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <libs/klibc.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>
#include <net/real_socket.h>
#include <bpf/socket_filter.h>

static int netlink_socket_fsid = 0;

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

static void netlink_buffer_init(struct netlink_buffer *buf) {
    memset(buf, 0, sizeof(struct netlink_buffer));
    buf->size = NETLINK_BUFFER_SIZE;
    buf->lock = SPIN_INIT;
}

// Circular buffer operations for netlink packets with sender info
size_t netlink_buffer_write_packet(struct netlink_sock *sock, const char *data,
                                   size_t len, uint32_t nl_pid,
                                   uint32_t nl_groups) {
    struct netlink_buffer *buf = sock->buffer;

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

    spin_lock(&buf->lock);

    // 计算可用空间
    size_t used;
    if (buf->tail >= buf->head) {
        used = buf->tail - buf->head;
    } else {
        used = buf->size - buf->head + buf->tail;
    }
    size_t available_space = buf->size - used - 1;

    // 检查是否有足够空间存储 包头 + 消息内容
    size_t total_needed = sizeof(struct netlink_packet_hdr) + len;
    if (available_space < total_needed) {
        spin_unlock(&buf->lock);
        return 0; // 没有足够空间
    }

    // 准备包头
    struct netlink_packet_hdr hdr;
    hdr.nl_pid = nl_pid;
    hdr.nl_groups = nl_groups;
    hdr.length = (uint32_t)len;

    // 写入包头
    char *hdr_bytes = (char *)&hdr;
    for (size_t i = 0; i < sizeof(struct netlink_packet_hdr); i++) {
        buf->data[buf->tail] = hdr_bytes[i];
        buf->tail = (buf->tail + 1) % buf->size;
    }

    // 写入消息内容
    for (size_t i = 0; i < len; i++) {
        buf->data[buf->tail] = data[i];
        buf->tail = (buf->tail + 1) % buf->size;
    }

    spin_unlock(&buf->lock);
    return len;
}

// Read data from buffer with sender info
static size_t netlink_buffer_read_packet(struct netlink_sock *sock, char *out,
                                         size_t out_len, uint32_t *nl_pid,
                                         uint32_t *nl_groups, bool peek) {
    struct netlink_buffer *buf = sock->buffer;

    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);

    // 计算当前buffer中的数据量
    size_t available;
    if (buf->tail >= buf->head) {
        available = buf->tail - buf->head;
    } else {
        available = buf->size - buf->head + buf->tail;
    }

    // 至少需要包头大小
    if (available < sizeof(struct netlink_packet_hdr)) {
        spin_unlock(&buf->lock);
        return 0;
    }

    // 读取包头
    struct netlink_packet_hdr hdr;
    char *hdr_bytes = (char *)&hdr;
    size_t pos = buf->head;
    for (size_t i = 0; i < sizeof(struct netlink_packet_hdr); i++) {
        hdr_bytes[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    // 检查是否有完整消息
    if (available < sizeof(struct netlink_packet_hdr) + hdr.length) {
        spin_unlock(&buf->lock);
        return 0;
    }

    // 返回sender信息
    if (nl_pid)
        *nl_pid = hdr.nl_pid;
    if (nl_groups)
        *nl_groups = hdr.nl_groups;

    // 确定实际复制的长度
    size_t copy_len = 0;
    if (out != NULL && out_len > 0) {
        copy_len = (hdr.length < out_len) ? hdr.length : out_len;

        // 读取消息内容到输出缓冲区
        for (size_t i = 0; i < copy_len; i++) {
            out[i] = buf->data[pos];
            pos = (pos + 1) % buf->size;
        }

        // 如果消息长度大于输出缓冲区，跳过剩余部分
        for (size_t i = copy_len; i < hdr.length; i++) {
            pos = (pos + 1) % buf->size;
        }
    } else {
        // 没有输出 buffer，跳过整个消息
        for (size_t i = 0; i < hdr.length; i++) {
            pos = (pos + 1) % buf->size;
        }
        copy_len = hdr.length; // 返回消息实际长度
    }

    // 如果不是peek模式，更新head指针
    if (!peek) {
        buf->head = pos;
    }

    spin_unlock(&buf->lock);
    return copy_len;
}

// Check if a complete message is available
static bool netlink_buffer_has_msg(struct netlink_sock *sock) {
    struct netlink_buffer *buf = sock->buffer;

    if (buf == NULL) {
        return false;
    }

    spin_lock(&buf->lock);

    // 计算当前buffer中的数据量
    size_t available;
    if (buf->tail >= buf->head) {
        available = buf->tail - buf->head;
    } else {
        available = buf->size - buf->head + buf->tail;
    }

    if (available < sizeof(struct netlink_packet_hdr)) {
        spin_unlock(&buf->lock);
        return false;
    }

    struct netlink_packet_hdr hdr;
    char *hdr_bytes = (char *)&hdr;
    size_t pos = buf->head;
    for (size_t i = 0; i < sizeof(struct netlink_packet_hdr); i++) {
        hdr_bytes[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    bool has_complete_msg =
        (available >= sizeof(struct netlink_packet_hdr) + hdr.length);

    spin_unlock(&buf->lock);
    return has_complete_msg;
}

// Get the length of next message without consuming it
static size_t netlink_buffer_peek_msg_len(struct netlink_sock *sock) {
    struct netlink_buffer *buf = sock->buffer;

    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);

    size_t available;
    if (buf->tail >= buf->head) {
        available = buf->tail - buf->head;
    } else {
        available = buf->size - buf->head + buf->tail;
    }

    if (available < sizeof(struct netlink_packet_hdr)) {
        spin_unlock(&buf->lock);
        return 0;
    }

    struct netlink_packet_hdr hdr;
    char *hdr_bytes = (char *)&hdr;
    size_t pos = buf->head;
    for (size_t i = 0; i < sizeof(struct netlink_packet_hdr); i++) {
        hdr_bytes[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    // 检查完整性
    if (available < sizeof(struct netlink_packet_hdr) + hdr.length) {
        spin_unlock(&buf->lock);
        return 0;
    }

    spin_unlock(&buf->lock);
    return hdr.length;
}

static size_t netlink_buffer_available(struct netlink_buffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    spin_lock(&buf->lock);
    size_t avail;
    if (buf->tail >= buf->head) {
        avail = buf->tail - buf->head;
    } else {
        avail = buf->size - buf->head + buf->tail;
    }
    spin_unlock(&buf->lock);
    return avail;
}

static void netlink_deliver_historical_messages(struct netlink_sock *sock) {
    if (sock == NULL || sock->buffer == NULL || sock->groups == 0) {
        return;
    }

    spin_lock(&netlink_msg_pool_lock);

    int start = netlink_msg_pool_next;
    for (int count = 0; count < MAX_NETLINK_MSG_POOL_SIZE; count++) {
        int i = (start + count) % MAX_NETLINK_MSG_POOL_SIZE;
        struct netlink_msg_pool_entry *entry = &netlink_msg_pool[i];

        if (!entry->valid)
            continue;

        // 检查 protocol 和 groups 是否匹配
        if (entry->protocol != sock->protocol)
            continue;

        if (entry->nl_groups != sock->groups)
            continue;

        // 投递消息到 socket buffer
        size_t written =
            netlink_buffer_write_packet(sock, entry->message, entry->length,
                                        entry->nl_pid, entry->nl_groups);

        if (written == 0) {
            // Buffer 满了，停止投递
            break;
        }
    }

    spin_unlock(&netlink_msg_pool_lock);
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

        if (sock->groups == target_groups) {
            netlink_buffer_write_packet(sock, buf, len, sender_pid,
                                        target_groups);
        }

        spin_unlock(&sock->lock);
    }

    spin_unlock(&netlink_sockets_lock);
}

int netlink_bind(uint64_t fd, const struct sockaddr_un *addr,
                 socklen_t addrlen) {
    if (current_task->fd_info->fds[fd] == NULL ||
        current_task->fd_info->fds[fd]->node == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    if (handle == NULL || handle->sock == NULL) {
        return -EBADF;
    }

    struct netlink_sock *sock = handle->sock;
    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;

    if (nl_addr->nl_family != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }

    spin_lock(&sock->lock);

    sock->portid = nl_addr->nl_pid;
    sock->groups = nl_addr->nl_groups;

    if (sock->bind_addr == NULL) {
        sock->bind_addr = malloc(sizeof(struct sockaddr_nl));
        if (sock->bind_addr == NULL) {
            spin_unlock(&sock->lock);
            return -ENOMEM;
        }
    }
    memcpy(sock->bind_addr, nl_addr, sizeof(struct sockaddr_nl));
    sock->bind_addr->nl_pid = sock->portid;

    netlink_deliver_historical_messages(sock);

    spin_unlock(&sock->lock);

    return 0;
}

size_t netlink_getsockopt(uint64_t fd, int level, int optname, void *optval,
                          socklen_t *optlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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
        default:
            return -ENOPROTOOPT;
        }
    } else if (level == SOL_NETLINK) {
        return 0;
    } else {
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t netlink_setsockopt(uint64_t fd, int level, int optname,
                          const void *optval, socklen_t optlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_ATTACH_FILTER:
            struct sock_fprog *fprog = malloc(optlen);
            if (copy_from_user(fprog, optval, optlen)) {
                free(fprog);
                return (size_t)-EFAULT;
            }
            if (!fprog->len) {
                free(fprog);
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
                free(fprog);
                free(nl_sk->filter->filter);
                free(nl_sk->filter);
                return (size_t)-EFAULT;
            }
            free(fprog);
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
        default:
            return -ENOPROTOOPT;
        }
    } else if (level == SOL_NETLINK) {
        return 0;
    } else {
        return -ENOPROTOOPT;
    }

    return 0;
}

int netlink_getsockname(uint64_t fd, struct sockaddr_un *addr,
                        socklen_t *addrlen) {
    if (current_task->fd_info->fds[fd] == NULL) {
        return -EBADF;
    }

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->buffer == NULL) {
        return -EINVAL;
    }

    bool noblock = !!(flags & MSG_DONTWAIT) ||
                   !!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK);

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    while (!has_msg) {
        schedule(SCHED_FLAG_YIELD);
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
        nl_sk, temp_buf, sizeof(temp_buf), &sender_pid, &sender_groups, false);
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

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->buffer == NULL) {
        return -EINVAL;
    }

    bool noblock = !!(flags & MSG_DONTWAIT) ||
                   !!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK);

    bool peek = !!(flags & MSG_PEEK);

    size_t msg_len = netlink_buffer_peek_msg_len(nl_sk);
    if (peek && msg_len > 0)
        return msg_len;

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    while (!has_msg) {
        schedule(SCHED_FLAG_YIELD);
        has_msg = netlink_buffer_has_msg(nl_sk);
    }

    uint32_t sender_pid = 0;
    uint32_t sender_groups = 0;

    // 重新获取消息长度（用于 MSG_TRUNC）
    msg_len = netlink_buffer_peek_msg_len(nl_sk);

    char temp_buffer[NETLINK_BUFFER_SIZE];
    // Read the complete message directly into the user buffer
    size_t bytes_read = netlink_buffer_read_packet(
        nl_sk, temp_buffer, limit, &sender_pid, &sender_groups, false);
    if (bytes_read == 0) {
        return -EAGAIN;
    }

    if (copy_to_user(out, temp_buffer, bytes_read))
        return (size_t)-EFAULT;

    // Fill in socket address if requested
    if (addr) {
        struct sockaddr_nl nl_addr_out;
        nl_addr_out.nl_family = AF_NETLINK;
        nl_addr_out.nl_pid = sender_pid;
        nl_addr_out.nl_groups = sender_groups;
        nl_addr_out.nl_pad = 0;

        if (copy_to_user(addr, &nl_addr_out, sizeof(struct sockaddr_nl))) {
            return -EFAULT;
        }
    }

    if (len) {
        uint32_t addr_len = sizeof(struct sockaddr_nl);
        if (copy_to_user(len, &addr_len, sizeof(uint32_t))) {
            return -EFAULT;
        }
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

    vfs_node_t socknode = vfs_node_alloc(NULL, NULL);
    if (socknode == NULL) {
        free(handle);
        free(nl_sk->buffer);
        free(nl_sk);
        return -ENOMEM;
    }
    socknode->type = file_socket;
    socknode->fsid = netlink_socket_fsid;
    socknode->refcount++;
    socknode->handle = handle;

    handle->op = &netlink_ops;
    handle->sock = nl_sk;

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

    int ret = -EMFILE;
    uint64_t i = 0;
    with_fd_info_lock(current_task->fd_info, {
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL) {
                break;
            }
        }

        if (i == MAX_FD_NUM)
            break;

        fd_t *new_fd = malloc(sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }

        memset(new_fd, 0, sizeof(fd_t));
        new_fd->node = socknode;
        new_fd->offset = 0;
        new_fd->flags = flags;
        if (type & O_CLOEXEC) {
            new_fd->close_on_exec = true;
        }
        current_task->fd_info->fds[i] = new_fd;
        procfs_on_open_file(current_task, i);
        ret = (int)i;
    });

    if (ret < 0) {
        spin_lock(&netlink_sockets_lock);
        netlink_sockets[slot] = NULL;
        spin_unlock(&netlink_sockets_lock);
        vfs_free(socknode);
        return ret;
    }

    return ret;
}

int netlink_socket_pair(int type, int protocol, int *sv) {
    // Netlink doesn't support socketpair
    return -EOPNOTSUPP;
}

int netlink_poll(void *h, int events) {
    socket_handle_t *handle = h;
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

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    if (nl_sk->protocol == NETLINK_KOBJECT_UEVENT) {
        return count;
    }

    return -EDESTADDRREQ;
}

int netlink_ioctl(void *file, ssize_t cmd, ssize_t arg) { return -EINVAL; }

void netlink_free_handle(vfs_node_t node) {
    if (node == NULL) {
        return;
    }

    socket_handle_t *handle = node->handle;
    if (handle == NULL)
        return;

    struct netlink_sock *nl_sk = handle->sock;
    if (nl_sk != NULL) {
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
            free(nl_sk->buffer);
        }
        if (nl_sk->bind_addr != NULL) {
            free(nl_sk->bind_addr);
        }
        free(nl_sk);
    }

    free(handle);
    node->handle = NULL;
}

static int dummy() { return 0; }

static struct vfs_callback netlink_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .remount = (vfs_remount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)netlink_read,
    .write = (vfs_write_t)netlink_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)netlink_ioctl,
    .poll = (vfs_poll_t)netlink_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = (vfs_free_handle_t)netlink_free_handle,
};

fs_t netlinksockfs = {
    .name = "netlinksockfs",
    .magic = 0,
    .callback = &netlink_callback,
    .flags = FS_FLAGS_HIDDEN,
};

void netlink_init() {
    netlink_socket_fsid = vfs_regist(&netlinksockfs);

    // Initialize message pool
    spin_lock(&netlink_msg_pool_lock);
    for (int i = 0; i < MAX_NETLINK_MSG_POOL_SIZE; i++) {
        netlink_msg_pool[i].valid = false;
    }
    netlink_msg_pool_next = 0;
    spin_unlock(&netlink_msg_pool_lock);

    regist_socket(16, NULL, netlink_socket);
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
