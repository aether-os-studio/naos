#include <net/netlink.h>
#include <task/task.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <libs/klibc.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/proc.h>
#include <net/real_socket.h>

extern vfs_node_t sockfs_root;
extern int sockfsfd_id;

static int netlink_socket_fsid = 0;

// Global netlink socket tracking
#define MAX_NETLINK_SOCKETS 64
static struct netlink_sock *netlink_sockets[MAX_NETLINK_SOCKETS] = {0};
static spinlock_t netlink_sockets_lock = SPIN_INIT;

// Uevent message pool for persistent storage
#define MAX_UEVENT_POOL_SIZE 256
struct uevent_pool_entry {
    char message[NETLINK_BUFFER_SIZE];
    size_t length;
    uint64_t timestamp;
    uint32_t seqnum;
    char devpath[256];
    bool valid;
};

static struct uevent_pool_entry uevent_pool[MAX_UEVENT_POOL_SIZE];
static uint32_t uevent_pool_next = 0;
static spinlock_t uevent_pool_lock = SPIN_INIT;

// Function to add uevent to persistent pool
static void uevent_pool_add(const char *message, size_t length, uint32_t seqnum,
                            const char *devpath) {
    spin_lock(&uevent_pool_lock);

    struct uevent_pool_entry *entry = &uevent_pool[uevent_pool_next];
    entry->valid = true;
    entry->length =
        (length < NETLINK_BUFFER_SIZE) ? length : NETLINK_BUFFER_SIZE - 1;
    memcpy(entry->message, message, entry->length);
    entry->message[entry->length] = '\0';
    entry->timestamp = 0; // TODO: Get current time
    entry->seqnum = seqnum;
    if (devpath) {
        strncpy(entry->devpath, devpath, sizeof(entry->devpath) - 1);
        entry->devpath[sizeof(entry->devpath) - 1] = '\0';
    } else {
        entry->devpath[0] = '\0';
    }

    uevent_pool_next = (uevent_pool_next + 1) % MAX_UEVENT_POOL_SIZE;

    spin_unlock(&uevent_pool_lock);
}

// Function to retrieve uevent from pool by seqnum
static bool uevent_pool_get_by_seqnum(uint32_t seqnum, char *buffer,
                                      size_t *length) {
    spin_lock(&uevent_pool_lock);
    bool found = false;

    for (int i = 0; i < MAX_UEVENT_POOL_SIZE; i++) {
        struct uevent_pool_entry *entry = &uevent_pool[i];
        if (entry->valid && entry->seqnum == seqnum) {
            size_t copy_len =
                (entry->length < *length) ? entry->length : *length;
            memcpy(buffer, entry->message, copy_len);
            *length = copy_len;
            found = true;
            break;
        }
    }

    spin_unlock(&uevent_pool_lock);
    return found;
}

// Function to retrieve uevent from pool by devpath
static bool uevent_pool_get_by_devpath(const char *devpath, char *buffer,
                                       size_t *length) {
    spin_lock(&uevent_pool_lock);
    bool found = false;

    for (int i = 0; i < MAX_UEVENT_POOL_SIZE; i++) {
        struct uevent_pool_entry *entry = &uevent_pool[i];
        if (entry->valid && strcmp(entry->devpath, devpath) == 0) {
            size_t copy_len =
                (entry->length < *length) ? entry->length : *length;
            memcpy(buffer, entry->message, copy_len);
            *length = copy_len;
            found = true;
            break;
        }
    }

    spin_unlock(&uevent_pool_lock);
    return found;
}

// Circular buffer operations for string messages
static size_t netlink_buffer_write_msg(struct netlink_buffer *buf,
                                       const char *data, size_t len) {
    spin_lock(&buf->lock);

    // 计算可用空间
    size_t available_space;
    if (buf->tail >= buf->head) {
        available_space = buf->size - (buf->tail - buf->head) - 1;
    } else {
        available_space = buf->head - buf->tail - 1;
    }

    // 检查是否有足够空间存储 长度(4字节) + 消息内容
    size_t total_needed = sizeof(uint32_t) + len;
    if (available_space < total_needed) {
        spin_unlock(&buf->lock);
        return 0; // 没有足够空间
    }

    // 写入4字节长度前缀
    uint32_t msg_len = (uint32_t)len;
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        buf->data[buf->tail] = ((char *)&msg_len)[i];
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

// Read data from buffer, stopping at message boundary (null terminator)
static size_t netlink_buffer_read_msg(struct netlink_buffer *buf, char *out,
                                      size_t out_len, bool peek) {
    spin_lock(&buf->lock);

    // 计算当前buffer中的数据量
    size_t available;
    if (buf->tail >= buf->head) {
        available = buf->tail - buf->head;
    } else {
        available = buf->size - buf->head + buf->tail;
    }

    // 至少需要4字节的长度头
    if (available < sizeof(uint32_t)) {
        spin_unlock(&buf->lock);
        return 0;
    }

    // 读取长度头
    uint32_t msg_len = 0;
    size_t pos = buf->head;
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        ((char *)&msg_len)[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    // 检查是否有完整消息
    if (available < sizeof(uint32_t) + msg_len) {
        spin_unlock(&buf->lock);
        return 0;
    }

    // 确定实际复制的长度
    size_t copy_len = (msg_len < out_len) ? msg_len : out_len;

    // 读取消息内容到输出缓冲区
    for (size_t i = 0; i < copy_len; i++) {
        out[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    // 如果消息长度大于输出缓冲区，跳过剩余部分
    for (size_t i = copy_len; i < msg_len; i++) {
        pos = (pos + 1) % buf->size;
    }

    // 如果不是peek模式，更新head指针
    if (!peek) {
        buf->head = pos;
    }

    spin_unlock(&buf->lock);
    return copy_len;
}

// Check if a complete message is available
static bool netlink_buffer_has_msg(struct netlink_buffer *buf) {
    spin_lock(&buf->lock);

    // 计算当前buffer中的数据量
    size_t available;
    if (buf->tail >= buf->head) {
        available = buf->tail - buf->head;
    } else {
        available = buf->size - buf->head + buf->tail;
    }

    if (available < sizeof(uint32_t)) {
        spin_unlock(&buf->lock);
        return false;
    }

    uint32_t msg_len = 0;
    size_t pos = buf->head;
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        ((char *)&msg_len)[i] = buf->data[pos];
        pos = (pos + 1) % buf->size;
    }

    bool has_complete_msg = (available >= sizeof(uint32_t) + msg_len);

    spin_unlock(&buf->lock);
    return has_complete_msg;
}

// Function to deliver historical uevents to a new socket
static void netlink_deliver_historical_uevents(struct netlink_sock *sock) {
    spin_lock(&uevent_pool_lock);

    for (int i = 0; i < MAX_UEVENT_POOL_SIZE; i++) {
        struct uevent_pool_entry *entry = &uevent_pool[i];
        if (!entry->valid)
            continue;

        size_t written = netlink_buffer_write_msg(sock->buffer, entry->message,
                                                  entry->length);

        if (written == 0) {
            break;
        }
    }

    spin_unlock(&uevent_pool_lock);
}

static void netlink_buffer_init(struct netlink_buffer *buf) {
    memset(buf, 0, sizeof(struct netlink_buffer));
    buf->size = NETLINK_BUFFER_SIZE;
    buf->lock = SPIN_INIT;
}

static size_t netlink_buffer_available(struct netlink_buffer *buf) {
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

// Netlink socket operations
int netlink_bind(uint64_t fd, const struct sockaddr_un *addr,
                 socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
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
    }
    memcpy(sock->bind_addr, nl_addr, sizeof(struct sockaddr_nl));

    spin_unlock(&sock->lock);

    return 0;
}

size_t netlink_getsockopt(uint64_t fd, int level, int optname,
                          const void *optval, socklen_t *optlen) {
    // TODO: Implement netlink socket options
    return 0;
}

size_t netlink_setsockopt(uint64_t fd, int level, int optname,
                          const void *optval, socklen_t optlen) {
    // TODO: Implement netlink socket options
    return 0;
}

int netlink_getsockname(uint64_t fd, struct sockaddr_un *addr,
                        socklen_t *addrlen) {
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
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    bool noblock = !!(flags & MSG_DONTWAIT) ||
                   !!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK);

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk->buffer);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    if (!has_msg && !noblock) {
        while (!has_msg) {
            arch_pause();
            has_msg = netlink_buffer_has_msg(nl_sk->buffer);
        }
    }

    if (!has_msg) {
        return 0;
    }

    char temp_buf[NETLINK_BUFFER_SIZE];
    // Read the complete message into a temporary buffer
    size_t bytes_read = netlink_buffer_read_msg(nl_sk->buffer, temp_buf,
                                                sizeof(temp_buf), false);
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

    // If we couldn't copy the entire message, we have a problem
    if (remaining > 0) {
        return -EFAULT;
    }

    // Fill in ancillary data if requested
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
    if (cmsg) {
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;

        struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
        cred->pid = current_task->pid;
        cred->gid = 0;
        cred->uid = 0;

        msg->msg_controllen = cmsg->cmsg_len;
    }

    // Fill in socket address if requested
    if (msg->msg_name) {
        struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)msg->msg_name;
        nl_addr->nl_family = AF_NETLINK;
        nl_addr->nl_pid = 0; // Kernel pid
        nl_addr->nl_groups = 1;
        nl_addr->nl_pad = 0;
        msg->msg_namelen = sizeof(struct sockaddr_nl);
    }

    return total_copied;
}

size_t netlink_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    // Calculate total message length
    size_t total_len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].len;
    }

    if (total_len > NETLINK_BUFFER_SIZE) {
        return -EMSGSIZE;
    }

    // Copy data into buffer
    char buffer[NETLINK_BUFFER_SIZE];
    size_t offset = 0;

    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        memcpy(buffer + offset, curr->iov_base, curr->len);
        offset += curr->len;
    }

    // Ensure null termination for uevent messages
    if (offset > 0 && offset < NETLINK_BUFFER_SIZE) {
        buffer[offset] = '\0';
    }

    // For uevent protocol, broadcast the message
    // TODO: Handle other netlink protocols
    printk("netlink sendmsg: received %zu bytes for uevent\n", total_len);

    return total_len;
}

size_t netlink_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags,
                      struct sockaddr_un *addr, uint32_t len) {
    // TODO: Implement netlink sendto
    return len;
}

size_t netlink_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags,
                        struct sockaddr_un *addr, uint32_t *len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *nl_sk = handle->sock;

    bool noblock = !!(flags & MSG_DONTWAIT) ||
                   !!(current_task->fd_info->fds[fd]->flags & O_NONBLOCK);

    // Check if there's a complete message available
    bool has_msg = netlink_buffer_has_msg(nl_sk->buffer);
    if (!has_msg && noblock) {
        return -EAGAIN;
    }

    // Wait for a complete message if blocking
    if (!has_msg && !noblock) {
        while (!has_msg) {
            arch_pause();
            has_msg = netlink_buffer_has_msg(nl_sk->buffer);
        }
    }

    if (!has_msg) {
        return 0;
    }

    if (flags & MSG_PEEK) {
        char temp_buf[NETLINK_BUFFER_SIZE];
        size_t bytes_read = netlink_buffer_read_msg(nl_sk->buffer, temp_buf,
                                                    sizeof(temp_buf), true);
        return bytes_read;
    }

    // Read the complete message directly into the user buffer
    size_t bytes_read =
        netlink_buffer_read_msg(nl_sk->buffer, (char *)out, limit, false);
    if (bytes_read == 0) {
        return -EAGAIN;
    }

    // Fill in socket address if requested
    if (addr) {
        struct sockaddr_nl nl_addr;
        nl_addr.nl_family = AF_NETLINK;
        nl_addr.nl_pid = 0; // Kernel pid
        nl_addr.nl_groups = 1;
        nl_addr.nl_pad = 0;

        if (copy_to_user(addr, &nl_addr, sizeof(struct sockaddr_nl))) {
            return -EFAULT;
        }
    }

    if (len) {
        uint32_t addr_len = sizeof(struct sockaddr_nl);
        if (copy_to_user(len, &addr_len, sizeof(uint32_t))) {
            return -EFAULT;
        }
    }

    return bytes_read;
}

// Broadcast uevent to all listening netlink sockets
static void netlink_broadcast_uevent(const char *buf, int len, uint32_t seqnum,
                                     const char *devpath) {
    // Add to persistent pool
    uevent_pool_add(buf, len, seqnum, devpath);

    // Broadcast to all sockets subscribed to uevent group
    spin_lock(&netlink_sockets_lock);

    for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
        if (netlink_sockets[i] == NULL)
            continue;

        struct netlink_sock *sock = netlink_sockets[i];
        spin_lock(&sock->lock);

        // Check if socket is bound to uevent group (group 1)
        if (sock->groups & 1) {
            netlink_buffer_write_msg(sock->buffer, buf, len);
        }

        spin_unlock(&sock->lock);
    }

    spin_unlock(&netlink_sockets_lock);
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

    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);

    struct netlink_sock *nl_sk = malloc(sizeof(struct netlink_sock));
    memset(nl_sk, 0, sizeof(struct netlink_sock));

    nl_sk->portid = (uint32_t)current_task->pid;
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
    memset(handle, 0, sizeof(socket_handle_t));

    vfs_node_t socknode = vfs_node_alloc(sockfs_root, buf);
    socknode->type = file_socket;
    socknode->fsid = netlink_socket_fsid;
    socknode->refcount++;
    socknode->handle = handle;

    handle->op = &netlink_ops;
    handle->sock = nl_sk;

    // Add to global socket array
    spin_lock(&netlink_sockets_lock);
    for (int i = 0; i < MAX_NETLINK_SOCKETS; i++) {
        if (netlink_sockets[i] == NULL) {
            netlink_sockets[i] = nl_sk;

            // If this is a uevent socket (NETLINK_KOBJECT_UEVENT protocol),
            // automatically subscribe to uevent group
            if (protocol == NETLINK_KOBJECT_UEVENT) {
                nl_sk->groups = 1; // Subscribe to uevent group
                // Deliver historical uevents to new socket
                netlink_deliver_historical_uevents(nl_sk);
            }

            break;
        }
    }
    spin_unlock(&netlink_sockets_lock);

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        free(nl_sk->buffer);
        free(nl_sk);
        free(handle);
        return -EBADF;
    }

    uint64_t flags = 0;
    if (type & O_NONBLOCK) {
        flags |= O_NONBLOCK;
    }
    if (type & O_CLOEXEC) {
        flags |= O_CLOEXEC;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = socknode;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = flags;
    procfs_on_open_file(current_task, i);

    return i;
}

int netlink_socket_pair(int type, int protocol, int *sv) {
    // TODO: Implement netlink socket pairs
    return -ENOSYS;
}

int netlink_poll(void *h, int events) {
    socket_handle_t *handle = h;
    struct netlink_sock *nl_sk = handle->sock;

    int revents = 0;

    spin_lock(&nl_sk->lock);
    bool has_msg = netlink_buffer_has_msg(nl_sk->buffer);
    spin_unlock(&nl_sk->lock);

    if (has_msg) {
        revents |= EPOLLIN;
    }

    // Always writable for now
    revents |= EPOLLOUT;

    return revents;
}

ssize_t netlink_read(uint64_t fd, char *buf, size_t count) {
    // Delegate to recvfrom with no address
    return netlink_recvfrom(fd, (uint8_t *)buf, count, 0, NULL, NULL);
}

ssize_t netlink_write(uint64_t fd, const char *buf, size_t count) {
    // Delegate to sendto with no address
    return netlink_sendto(fd, (const uint8_t *)buf, count, 0, NULL, 0);
}

void netlink_free_handle(vfs_node_t node) {
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
}

static int dummy() { return -ENOSYS; }

static struct vfs_callback netlink_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
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
    .ioctl = (vfs_ioctl_t)dummy,
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

    // Initialize uevent pool
    spin_lock(&uevent_pool_lock);
    for (int i = 0; i < MAX_UEVENT_POOL_SIZE; i++) {
        uevent_pool[i].valid = false;
    }
    uevent_pool_next = 0;
    spin_unlock(&uevent_pool_lock);

    regist_socket(16, netlink_socket);
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

    if (uevent_pool_get_by_devpath(devpath, buffer, &length)) {
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

        netlink_broadcast_uevent(buffer, length, seqnum, devpath);
    }
}

void netlink_kernel_uevent_send(const char *buf, int len) {
    if (len <= 0 || len > NETLINK_BUFFER_SIZE) {
        return;
    }

    // Extract seqnum from uevent message
    uint32_t seqnum = 0;
    char devpath[256] = {0};

    // Parse the uevent message to extract SEQNUM and DEVPATH
    const char *ptr = buf;
    while (*ptr) {
        if (strncmp(ptr, "SEQNUM=", 7) == 0) {
            seqnum = atoi(ptr + 7);
        } else if (strncmp(ptr, "DEVPATH=", 8) == 0) {
            const char *end = strchr(ptr, '\0');
            size_t path_len = end - (ptr + 8);
            if (path_len < sizeof(devpath)) {
                strncpy(devpath, ptr + 8, path_len);
                devpath[path_len] = '\0';
            }
        }
        ptr += strlen(ptr) + 1;
    }

    netlink_broadcast_uevent(buf, len, seqnum, devpath);
}
