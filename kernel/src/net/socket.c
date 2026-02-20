#include <arch/arch.h>
#include <net/net_syscall.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <task/task.h>
#include <net/netlink.h>
#include <libs/strerror.h>

extern socket_op_t socket_ops;

int sockfsfd_id = 0;

socket_t first_unix_socket;
spinlock_t unix_socket_list_lock;

int unix_socket_fsid = 0;

char *unix_socket_addr_safe(const struct sockaddr_un *addr, size_t len) {
    ssize_t addrLen = len - sizeof(addr->sun_family);
    if (addrLen <= 0)
        return (void *)-EINVAL;

    bool abstract = (addr->sun_path[0] == '\0');
    int skip = abstract ? 1 : 0;

    char *safe = malloc(addrLen + 3);
    if (!safe)
        return (void *)-(ENOMEM);
    memset(safe, 0, addrLen + 3);

    if (abstract && addr->sun_path[1] == '\0') {
        free(safe);
        return (char *)-EINVAL;
    }

    if (abstract) {
        safe[0] = '@';
        memcpy(safe + 1, addr->sun_path + skip, addrLen - skip);
    } else {
        memcpy(safe, addr->sun_path, addrLen);
    }

    return safe;
}

static const char *unix_socket_local_name(const socket_t *sock) {
    if (!sock)
        return "";
    if (sock->bindAddr && sock->bindAddr[0])
        return sock->bindAddr;
    if (sock->filename && sock->filename[0])
        return sock->filename;
    return "";
}

static void unix_socket_write_sockaddr(const char *name,
                                       struct sockaddr_un *addr,
                                       socklen_t *addrlen) {
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = 1;
    *addrlen = sizeof(addr->sun_family);

    if (!name || !name[0])
        return;

    size_t max_path = sizeof(addr->sun_path);
    size_t raw_len = strlen(name);

    if (name[0] == '@') {
        size_t n = MIN(raw_len - 1, max_path - 1);
        addr->sun_path[0] = '\0';
        if (n > 0)
            memcpy(addr->sun_path + 1, name + 1, n);
        *addrlen += 1 + n;
    } else {
        size_t n = MIN(raw_len, max_path - 1);
        memcpy(addr->sun_path, name, n);
        *addrlen += n + 1;
    }
}

socket_t *unix_socket_alloc() {
    socket_t *sock = malloc(sizeof(socket_t));
    memset(sock, 0, sizeof(socket_t));
    mutex_init(&sock->lock);

    sock->recv_size = BUFFER_SIZE;
    sock->recv_buff = alloc_frames_bytes(BUFFER_SIZE);
    sock->recv_pos = 0;

    memset(sock->pending_files, 0, sizeof(sock->pending_files));
    sock->has_pending_cred = false;

    // 设置凭据
    sock->cred.pid = current_task->pid;
    sock->cred.uid = current_task->uid;
    sock->cred.gid = current_task->gid;

    // 加入链表
    spin_lock(&unix_socket_list_lock);
    socket_t *head = &first_unix_socket;
    while (head->next)
        head = head->next;
    head->next = sock;
    spin_unlock(&unix_socket_list_lock);

    return sock;
}

void unix_socket_free(socket_t *sock) {
    // 从链表移除
    spin_lock(&unix_socket_list_lock);
    socket_t *browse = &first_unix_socket;
    while (browse && browse->next != sock)
        browse = browse->next;
    if (browse)
        browse->next = sock->next;
    spin_unlock(&unix_socket_list_lock);

    // 释放资源
    if (sock->recv_buff)
        free_frames_bytes(sock->recv_buff, sock->recv_size);
    if (sock->bindAddr)
        free(sock->bindAddr);
    if (sock->filename)
        free(sock->filename);
    if (sock->backlog)
        free(sock->backlog);
    if (sock->filter)
        free(sock->filter);

    // 清理 pending files
    for (int i = 0; i < MAX_PENDING_FILES_COUNT; i++) {
        if (sock->pending_files[i]) {
            free(sock->pending_files[i]);
        }
    }

    free(sock);
}

// 发送数据到对端的 recv_buff
static size_t unix_socket_send_to_peer(socket_t *self, socket_t *peer,
                                       const uint8_t *data, size_t len,
                                       int flags, fd_t *fd_handle) {
    socket_t *active_peer = peer;
    if (self && self->type != 2)
        active_peer = self->peer;

    if (self && self->shut_wr) {
        if (!(flags & MSG_NOSIGNAL))
            task_commit_signal(current_task, SIGPIPE, NULL);
        return -EPIPE;
    }

    if (!active_peer || active_peer->closed || active_peer->shut_rd) {
        if (!(flags & MSG_NOSIGNAL))
            task_commit_signal(current_task, SIGPIPE, NULL);
        return -EPIPE;
    }

    if (!len)
        return 0;

    while (true) {
        arch_enable_interrupt();

        if (self && self->type != 2)
            active_peer = self->peer;
        if (!active_peer) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            arch_disable_interrupt();
            return -EPIPE;
        }

        mutex_lock(&active_peer->lock);
        if (active_peer->closed || active_peer->shut_rd) {
            mutex_unlock(&active_peer->lock);
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            arch_disable_interrupt();
            return -EPIPE;
        }
        size_t available = active_peer->recv_size - active_peer->recv_pos;
        if (available > 0) {
            size_t to_copy = MIN(len, available);
            memcpy(&active_peer->recv_buff[active_peer->recv_pos], data,
                   to_copy);
            active_peer->recv_pos += to_copy;
            mutex_unlock(&active_peer->lock);
            arch_disable_interrupt();
            return to_copy;
        }
        mutex_unlock(&active_peer->lock);

        if ((fd_handle && fd_handle->flags & O_NONBLOCK) ||
            (flags & MSG_DONTWAIT)) {
            arch_disable_interrupt();
            return -(EWOULDBLOCK);
        }

        schedule(SCHED_FLAG_YIELD);
    }

    return 0;
}

// 从自己的 recv_buff 接收数据
static size_t unix_socket_recv_from_self(socket_t *self, socket_t *peer,
                                         uint8_t *buf, size_t len, int flags,
                                         fd_t *fd_handle) {
    bool peek = !!(flags & MSG_PEEK);

    if (self->shut_rd)
        return 0;
    if (!len)
        return 0;

    // 等待数据
    while (true) {
        arch_enable_interrupt();

        mutex_lock(&self->lock);

        if (self->recv_pos > 0) {
            size_t to_copy = MIN(len, self->recv_pos);
            memcpy(buf, self->recv_buff, to_copy);
            if (!peek) {
                memmove(self->recv_buff, &self->recv_buff[to_copy],
                        self->recv_pos - to_copy);
                self->recv_pos -= to_copy;
            }
            mutex_unlock(&self->lock);
            arch_disable_interrupt();
            return to_copy;
        }

        socket_t *active_peer = peer;
        if (self->type != 2)
            active_peer = self->peer;
        bool eof =
            (!active_peer || active_peer->closed || active_peer->shut_wr);
        mutex_unlock(&self->lock);

        // 对端关闭且没有数据 = EOF
        if (eof) {
            arch_disable_interrupt();
            return 0;
        }

        if ((fd_handle && fd_handle->flags & O_NONBLOCK) ||
            (flags & MSG_DONTWAIT)) {
            arch_disable_interrupt();
            return -(EWOULDBLOCK);
        }

        schedule(SCHED_FLAG_YIELD);
    }
}

// 发送 pending files 到对端
static int unix_socket_send_files_to_peer(socket_t *peer, int *fds,
                                          int num_fds) {
    if (!peer)
        return -EINVAL;

    int free_slots = 0;
    for (int i = 0; i < MAX_PENDING_FILES_COUNT; i++) {
        if (!peer->pending_files[i])
            free_slots++;
    }
    if (free_slots < num_fds)
        return -ETOOMANYREFS;

    for (int i = 0; i < num_fds; i++) {
        int fd = fds[i];
        if (fd < 0 || fd >= MAX_FD_NUM)
            return -EBADF;
        if (!current_task->fd_info->fds[fd])
            return -EBADF;

        bool inserted = false;
        for (int j = 0; j < MAX_PENDING_FILES_COUNT; j++) {
            if (peer->pending_files[j] == NULL) {
                peer->pending_files[j] = malloc(sizeof(fd_t));
                if (!peer->pending_files[j])
                    return -ENOMEM;
                memcpy(peer->pending_files[j], current_task->fd_info->fds[fd],
                       sizeof(fd_t));
                peer->pending_files[j]->node->refcount++;
                inserted = true;
                break;
            }
        }
        if (!inserted)
            return -ETOOMANYREFS;
    }
    return 0;
}

// 从自己的 pending_files 接收
static size_t unix_socket_recv_files_from_self(socket_t *self, int *fds_out,
                                               size_t max_fds, int *msg_flags,
                                               int recv_flags) {
    size_t received = 0;

    for (int i = 0; i < MAX_PENDING_FILES_COUNT && received < max_fds; i++) {
        if (self->pending_files[i] == NULL)
            continue;

        int new_fd = -1;
        bool install_ok = false;
        with_fd_info_lock(current_task->fd_info, {
            for (int fd_idx = 0; fd_idx < MAX_FD_NUM; fd_idx++) {
                if (current_task->fd_info->fds[fd_idx] == NULL) {
                    new_fd = fd_idx;
                    break;
                }
            }

            if (new_fd < 0)
                break;

            fd_t *new_entry = malloc(sizeof(fd_t));
            if (!new_entry) {
                new_fd = -1;
                break;
            }

            memcpy(new_entry, self->pending_files[i], sizeof(fd_t));
            new_entry->close_on_exec = !!(recv_flags & MSG_CMSG_CLOEXEC);
            current_task->fd_info->fds[new_fd] = new_entry;
            install_ok = true;
        });

        if (!install_ok) {
            if (msg_flags)
                *msg_flags |= MSG_CTRUNC;
            break;
        }

        free(self->pending_files[i]);
        self->pending_files[i] = NULL;

        fds_out[received++] = new_fd;
        procfs_on_open_file(current_task, new_fd);
    }

    return received;
}

// 发送凭据到对端
static void unix_socket_send_cred_to_peer(socket_t *peer, struct ucred *cred) {
    if (!peer)
        return;
    memcpy(&peer->pending_cred, cred, sizeof(struct ucred));
    peer->has_pending_cred = true;
}

// 从自己的 pending_cred 接收
static bool unix_socket_recv_cred_from_self(socket_t *self,
                                            struct ucred *cred_out) {
    if (self->has_pending_cred) {
        memcpy(cred_out, &self->pending_cred, sizeof(struct ucred));
        self->has_pending_cred = false;
        return true;
    }
    return false;
}

vfs_node_t unix_socket_create_node(socket_t *sock) {
    vfs_node_t socknode = vfs_node_alloc(NULL, NULL);
    socknode->refcount++;
    socknode->type = file_socket;
    socknode->mode = 0700;
    socknode->fsid = unix_socket_fsid;

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    handle->op = &socket_ops;
    handle->sock = sock;

    socknode->handle = handle;
    return socknode;
}

int socket_socket(int domain, int type, int protocol) {
    socket_t *sock = unix_socket_alloc();

    sock->domain = domain;
    sock->type = type & 0xF;
    sock->protocol = protocol;

    vfs_node_t socknode = unix_socket_create_node(sock);
    socket_handle_t *handle = socknode->handle;

    int ret = -EMFILE;
    uint64_t i = 0;
    with_fd_info_lock(current_task->fd_info, {
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL)
                break;
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
        if (type & O_NONBLOCK)
            new_fd->flags |= O_NONBLOCK;
        new_fd->close_on_exec = !!(type & O_CLOEXEC);
        current_task->fd_info->fds[i] = new_fd;
        procfs_on_open_file(current_task, i);
        ret = (int)i;
    });

    if (ret < 0) {
        unix_socket_free(sock);
        vfs_free(socknode);
        return ret;
    }

    handle->fd = current_task->fd_info->fds[i];

    return ret;
}

int socket_bind(uint64_t fd, const struct sockaddr_un *addr,
                socklen_t addrlen) {
    if (!addr)
        return -EFAULT;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->bindAddr)
        return -EINVAL;

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;

    bool is_abstract = (addr->sun_path[0] == '\0');

    // 检查地址是否已被使用
    size_t safeLen = strlen(safe);
    spin_lock(&unix_socket_list_lock);
    socket_t *browse = &first_unix_socket;
    while (browse) {
        if (browse != sock && browse->bindAddr &&
            strlen(browse->bindAddr) == safeLen &&
            memcmp(safe, browse->bindAddr, safeLen) == 0) {
            free(safe);
            spin_unlock(&unix_socket_list_lock);
            return -EADDRINUSE;
        }
        browse = browse->next;
    }
    spin_unlock(&unix_socket_list_lock);

    if (!is_abstract) {
        if (vfs_open(safe, 0)) {
            free(safe);
            return -EADDRINUSE;
        }
        int mkret = vfs_mknod(safe, S_IFSOCK | 0666, 0);
        if (mkret < 0) {
            free(safe);
            return mkret;
        }
    }

    sock->bindAddr = strdup(safe);
    free(safe);
    return 0;
}

int socket_listen(uint64_t fd, int backlog) {
    if (backlog == 0)
        backlog = 16;
    if (backlog < 0)
        backlog = 0;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    mutex_lock(&sock->lock);
    if (sock->backlog) {
        free(sock->backlog);
        sock->backlog = NULL;
    }
    sock->connMax = backlog;
    sock->backlog = calloc(sock->connMax, sizeof(socket_t *));
    sock->connCurr = 0;
    mutex_unlock(&sock->lock);
    return 0;
}

int socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen,
                  uint64_t flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *listen_sock = handle->sock;

    if (flags & ~(O_CLOEXEC | O_NONBLOCK))
        return -EINVAL;

    if (addr && !addrlen)
        return -EFAULT;

    if (!listen_sock->connMax || !listen_sock->backlog)
        return -EINVAL;

    // 等待连接并从 backlog 取一个
    socket_t *server_sock = NULL;
    while (true) {
        mutex_lock(&listen_sock->lock);
        if (listen_sock->connCurr > 0) {
            server_sock = listen_sock->backlog[0];
            listen_sock->backlog[0] = NULL;
            if (listen_sock->connCurr > 1) {
                memmove(listen_sock->backlog, &listen_sock->backlog[1],
                        (listen_sock->connCurr - 1) * sizeof(socket_t *));
            }
            listen_sock->connCurr--;
            mutex_unlock(&listen_sock->lock);
            break;
        }
        mutex_unlock(&listen_sock->lock);
        if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK) {
            return -(EWOULDBLOCK);
        }
        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
    }
    arch_disable_interrupt();

    if (!server_sock)
        return -ECONNABORTED;

    // 创建节点
    vfs_node_t acceptFd = unix_socket_create_node(server_sock);

    int ret = -EMFILE;
    uint64_t i = 0;
    with_fd_info_lock(current_task->fd_info, {
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL)
                break;
        }

        if (i == MAX_FD_NUM)
            break;

        fd_t *new_fd = malloc(sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }

        memset(new_fd, 0, sizeof(fd_t));
        new_fd->node = acceptFd;
        new_fd->offset = 0;
        if (flags & O_NONBLOCK)
            new_fd->flags |= O_NONBLOCK;
        new_fd->close_on_exec = !!(flags & O_CLOEXEC);
        current_task->fd_info->fds[i] = new_fd;
        procfs_on_open_file(current_task, i);
        ret = (int)i;
    });

    if (ret < 0) {
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
        }
        unix_socket_free(server_sock);
        vfs_free(acceptFd);
        return ret;
    }

    socket_handle_t *accept_handle = acceptFd->handle;
    accept_handle->fd = current_task->fd_info->fds[i];

    if (addr) {
        struct sockaddr_un kaddr;
        socklen_t kaddrlen = 0;
        const char *name = unix_socket_local_name(server_sock->peer);
        unix_socket_write_sockaddr(name, &kaddr, &kaddrlen);

        socklen_t user_len = *addrlen;
        size_t copy_len = MIN((size_t)user_len, (size_t)kaddrlen);
        if (copy_len > 0)
            memcpy(addr, &kaddr, copy_len);
        *addrlen = kaddrlen;
    }

    return ret;
}

uint64_t socket_shutdown(uint64_t fd, uint64_t how) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;
    if (how > SHUT_RDWR)
        return -EINVAL;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->type == 1 && !sock->peer && !sock->established &&
        sock->connMax == 0)
        return -ENOTCONN;

    if (how == SHUT_RD || how == SHUT_RDWR)
        sock->shut_rd = true;
    if (how == SHUT_WR || how == SHUT_RDWR)
        sock->shut_wr = true;

    return 0;
}

int socket_connect(uint64_t fd, const struct sockaddr_un *addr,
                   socklen_t addrlen) {
    if (!addr)
        return -EFAULT;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->connMax != 0)
        return -(ECONNREFUSED);

    if (sock->peer)
        return -(EISCONN);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;
    size_t safeLen = strlen(safe);
    bool is_abstract = (addr->sun_path[0] == '\0');

    // 找监听的 socket
    spin_lock(&unix_socket_list_lock);
    socket_t *listen_sock = first_unix_socket.next;
    while (listen_sock) {
        if (listen_sock != sock && listen_sock->bindAddr &&
            strlen(listen_sock->bindAddr) == safeLen &&
            memcmp(safe, listen_sock->bindAddr, safeLen) == 0)
            break;
        listen_sock = listen_sock->next;
    }
    spin_unlock(&unix_socket_list_lock);

    if (!listen_sock) {
        int ret = -ENOENT;
        if (!is_abstract && vfs_open(safe, 0))
            ret = -ECONNREFUSED;
        free(safe);
        return ret;
    }
    free(safe);

    while (true) {
        mutex_lock(&listen_sock->lock);
        if (!listen_sock->connMax || !listen_sock->backlog) {
            mutex_unlock(&listen_sock->lock);
            return -ECONNREFUSED;
        }
        bool queue_available = listen_sock->connCurr < listen_sock->connMax;
        mutex_unlock(&listen_sock->lock);

        if (queue_available)
            break;

        if ((current_task->fd_info->fds[fd]->flags & O_NONBLOCK))
            return -EAGAIN;
        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
        arch_disable_interrupt();
    }

    socket_t *server_sock = unix_socket_alloc();
    if (!server_sock)
        return -ENOMEM;

    server_sock->domain = listen_sock->domain;
    server_sock->type = listen_sock->type;
    server_sock->protocol = listen_sock->protocol;
    server_sock->cred = listen_sock->cred;
    server_sock->passcred = listen_sock->passcred;
    if (listen_sock->bindAddr) {
        server_sock->filename = strdup(listen_sock->bindAddr);
        if (!server_sock->filename) {
            unix_socket_free(server_sock);
            return -ENOMEM;
        }
    }

    server_sock->peer = sock;
    sock->peer = server_sock;
    server_sock->established = true;
    sock->established = true;

    mutex_lock(&listen_sock->lock);
    if (!listen_sock->connMax || !listen_sock->backlog ||
        listen_sock->connCurr >= listen_sock->connMax) {
        mutex_unlock(&listen_sock->lock);
        sock->peer = NULL;
        sock->established = false;
        server_sock->peer = NULL;
        unix_socket_free(server_sock);
        return -ECONNREFUSED;
    }
    listen_sock->backlog[listen_sock->connCurr++] = server_sock;
    mutex_unlock(&listen_sock->lock);

    return 0;
}

size_t unix_socket_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags,
                          struct sockaddr_un *addr, uint32_t len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;

    if (!peer) {
        if (sock->type != 2 && sock->established) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return (size_t)-EPIPE;
        }

        if (addr && len) {
            char *safe = unix_socket_addr_safe(addr, len);
            if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
                return (uint64_t)safe;
            size_t safeLen = strlen(safe);

            // 找对端的 socket
            spin_lock(&unix_socket_list_lock);
            socket_t *peer_sock = first_unix_socket.next;
            while (peer_sock) {
                if (peer_sock != sock && peer_sock->bindAddr &&
                    strlen(peer_sock->bindAddr) == safeLen &&
                    memcmp(safe, peer_sock->bindAddr, safeLen) == 0)
                    break;
                peer_sock = peer_sock->next;
            }
            spin_unlock(&unix_socket_list_lock);
            free(safe);

            if (peer_sock) {
                peer = peer_sock;
                goto done;
            }
        }
        return (size_t)-ENOTCONN;
    }

done:
    return unix_socket_send_to_peer(sock, peer, in, limit, flags, caller_fd);
}

size_t unix_socket_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags,
                            struct sockaddr_un *addr, uint32_t *len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;

    if (sock->type != 2 && !sock->peer && !sock->established &&
        sock->recv_pos == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, out, limit, flags,
                                      caller_fd);
}

size_t unix_socket_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;

    if (!peer) {
        if (sock->type != 2 && sock->established) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return (size_t)-EPIPE;
        }

        if (msg->msg_name && msg->msg_namelen) {
            char *safe = unix_socket_addr_safe(msg->msg_name, msg->msg_namelen);
            if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
                return (uint64_t)safe;
            size_t safeLen = strlen(safe);

            // 找对端的 socket
            spin_lock(&unix_socket_list_lock);
            socket_t *peer_sock = first_unix_socket.next;
            while (peer_sock) {
                if (peer_sock != sock && peer_sock->bindAddr &&
                    strlen(peer_sock->bindAddr) == safeLen &&
                    memcmp(safe, peer_sock->bindAddr, safeLen) == 0)
                    break;
                peer_sock = peer_sock->next;
            }
            spin_unlock(&unix_socket_list_lock);
            free(safe);

            if (peer_sock) {
                peer = peer_sock;
                goto done;
            }
        }
        return (size_t)-ENOTCONN;
    }

done:
    // 处理控制消息
    if (msg->msg_control && msg->msg_controllen > 0) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        mutex_lock(&peer->lock);

        for (; cmsg != NULL; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET)
                continue;

            if (cmsg->cmsg_type == SCM_RIGHTS) {
                if (cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
                    mutex_unlock(&peer->lock);
                    return (size_t)-EINVAL;
                }
                size_t rights_len = cmsg->cmsg_len - CMSG_LEN(0);
                if ((rights_len % sizeof(int)) != 0) {
                    mutex_unlock(&peer->lock);
                    return (size_t)-EINVAL;
                }
                int *fds = (int *)CMSG_DATA(cmsg);
                int num_fds = rights_len / sizeof(int);
                int send_fds_ret =
                    unix_socket_send_files_to_peer(peer, fds, num_fds);
                if (send_fds_ret < 0) {
                    mutex_unlock(&peer->lock);
                    return (size_t)send_fds_ret;
                }
            } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
                if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct ucred))) {
                    printk("Invalid cmsg len for scm_credentials: %d\n",
                           cmsg->cmsg_len);
                    mutex_unlock(&peer->lock);
                    return (size_t)-EINVAL;
                }

                struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);

                // 验证凭据（非 root 只能发送自己的凭据）
                if (current_task->euid != 0) {
                    if (cred->pid != current_task->pid ||
                        cred->uid != current_task->uid ||
                        cred->gid != current_task->gid) {
                        mutex_unlock(&peer->lock);
                        return (size_t)-EPERM;
                    }
                }

                unix_socket_send_cred_to_peer(peer, cred);
            }
        }

        mutex_unlock(&peer->lock);
    }

    if (sock->passcred || peer->passcred) {
        struct ucred cred;
        cred.pid = current_task->pid;
        cred.uid = current_task->uid;
        cred.gid = current_task->gid;
        unix_socket_send_cred_to_peer(peer, &cred);
    }

    // 发送数据
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);

    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &((struct iovec *)msg->msg_iov)[i];
        size_t sent = 0;
        while (sent < curr->len) {
            const uint8_t *base = (const uint8_t *)curr->iov_base;
            size_t ret = unix_socket_send_to_peer(
                sock, peer, base + sent, curr->len - sent,
                noblock ? (flags | MSG_DONTWAIT) : flags, caller_fd);
            if ((int64_t)ret < 0) {
                if (cnt > 0 && ((int64_t)ret == -EAGAIN ||
                                (int64_t)ret == -EWOULDBLOCK)) {
                    return cnt;
                }
                return ret;
            }
            if (ret == 0)
                return cnt;
            sent += ret;
            cnt += ret;
        }
    }

    return cnt;
}

size_t unix_socket_recvmsg(uint64_t fd, struct msghdr *msg, int flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    if (!sock->peer && !sock->established && sock->recv_pos == 0)
        return (size_t)-ENOTCONN;

    bool noblock = !!(flags & MSG_DONTWAIT);
    msg->msg_flags = 0;

    // 等待数据
    while (!noblock && !(caller_fd->flags & O_NONBLOCK)) {
        mutex_lock(&sock->lock);
        socket_t *live_peer = sock->peer;
        bool has_data = sock->recv_pos > 0;
        bool eof = (!live_peer || live_peer->closed || live_peer->shut_wr);
        mutex_unlock(&sock->lock);
        if (has_data || eof)
            break;
        schedule(SCHED_FLAG_YIELD);
    }

    // 计算总长度并读取数据
    size_t len_total = 0;
    for (int i = 0; i < msg->msg_iovlen; i++)
        len_total += msg->msg_iov[i].len;

    char *buffer = malloc(len_total);
    size_t cnt = unix_socket_recv_from_self(
        sock, NULL, (uint8_t *)buffer, len_total,
        noblock ? (flags | MSG_DONTWAIT) : flags, caller_fd);

    if ((int64_t)cnt < 0) {
        free(buffer);
        return cnt;
    }

    // 分发到 iovec
    char *b = buffer;
    uint64_t remain = cnt;
    for (int i = 0; i < msg->msg_iovlen && remain > 0; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        size_t copy_len = MIN(curr->len, remain);
        memcpy(curr->iov_base, b, copy_len);
        b += copy_len;
        remain -= copy_len;
    }
    free(buffer);

    // 处理控制消息
    if (msg->msg_control && msg->msg_controllen >= sizeof(struct cmsghdr)) {
        size_t controllen_used = 0;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        mutex_lock(&sock->lock);

        // 处理 SCM_RIGHTS
        bool has_pending_fds = false;
        for (int i = 0; i < MAX_PENDING_FILES_COUNT; i++) {
            if (sock->pending_files[i] != NULL) {
                has_pending_fds = true;
                break;
            }
        }

        if (has_pending_fds && cmsg) {
            size_t space_left = msg->msg_controllen - controllen_used;
            if (space_left >= CMSG_SPACE(sizeof(int))) {
                size_t max_fds =
                    (space_left - sizeof(struct cmsghdr)) / sizeof(int);
                int *fds_out = (int *)CMSG_DATA(cmsg);

                size_t received_fds = unix_socket_recv_files_from_self(
                    sock, fds_out, max_fds, (int *)&msg->msg_flags, flags);

                if (received_fds > 0) {
                    cmsg->cmsg_level = SOL_SOCKET;
                    cmsg->cmsg_type = SCM_RIGHTS;
                    cmsg->cmsg_len = CMSG_LEN(received_fds * sizeof(int));
                    controllen_used += CMSG_SPACE(received_fds * sizeof(int));
                    cmsg = CMSG_NXTHDR(msg, cmsg);
                }
            } else {
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        // 处理 SCM_CREDENTIALS
        bool should_send_cred = (sock->passcred || sock->has_pending_cred);
        if (should_send_cred && cmsg) {
            size_t space_left = msg->msg_controllen - controllen_used;

            if (space_left >= CMSG_SPACE(sizeof(struct ucred))) {
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));

                struct ucred *cred_out = (struct ucred *)CMSG_DATA(cmsg);

                if (!unix_socket_recv_cred_from_self(sock, cred_out)) {
                    // 没有 pending cred，使用对端凭据
                    if (sock->peer)
                        memcpy(cred_out, &sock->peer->cred,
                               sizeof(struct ucred));
                }

                controllen_used += CMSG_SPACE(sizeof(struct ucred));
            } else {
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        mutex_unlock(&sock->lock);
        msg->msg_controllen = controllen_used;
    } else {
        msg->msg_controllen = 0;
    }

    return cnt;
}

int socket_poll(void *file, int events) {
    socket_handle_t *handler = file;
    socket_t *sock = handler->sock;
    int revents = 0;

    if (sock->connMax > 0) {
        // listen 模式
        if (sock->connCurr < sock->connMax)
            revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
        if (sock->connCurr > 0)
            revents |= (events & EPOLLIN) ? EPOLLIN : 0;
    } else if (sock->peer) {
        mutex_lock(&sock->lock);

        if (sock->peer->closed || sock->peer->shut_wr)
            revents |= EPOLLHUP;

        // 可写：对端有空间
        if ((events & EPOLLOUT) && !sock->shut_wr && !sock->peer->closed &&
            sock->peer->recv_pos < sock->peer->recv_size)
            revents |= EPOLLOUT;

        // 可读：自己有数据
        if ((events & EPOLLIN) && (sock->recv_pos > 0 || sock->shut_rd ||
                                   sock->peer->shut_wr || sock->peer->closed))
            revents |= EPOLLIN;

        mutex_unlock(&sock->lock);
    } else if (sock->type == 2) {
        if (events & EPOLLOUT)
            revents |= EPOLLOUT;

        if ((events & EPOLLIN) && sock->recv_pos > 0)
            revents |= EPOLLIN;
    } else {
        if ((events & EPOLLIN) && sock->established)
            revents |= EPOLLIN;
        revents |= EPOLLHUP;
    }

    return revents;
}

int socket_ioctl(void *file, ssize_t cmd, ssize_t arg) {
    socket_handle_t *handler = file;
    if (!handler || !handler->fd || !handler->sock)
        return -EBADF;

    socket_t *sock = handler->sock;

    switch (cmd) {
    case FIONBIO: {
        if (!arg)
            return -EFAULT;
        int value = *(int *)arg;
        if (value)
            handler->fd->flags |= O_NONBLOCK;
        else
            handler->fd->flags &= ~O_NONBLOCK;
        return 0;
    }
    case FIONREAD:
        if (!arg)
            return -EFAULT;
        *(int *)arg = (int)sock->recv_pos;
        return 0;
    default:
        return -ENOTTY;
    }
}

bool socket_close(socket_handle_t *handle) {
    if (!handle)
        return true;

    socket_t *sock = handle->sock;

    // 标记关闭
    sock->closed = true;

    // 断开与对端的连接
    if (sock->peer) {
        sock->peer->peer = NULL; // 对端不再指向我
        sock->peer = NULL;
    }

    unix_socket_free(sock);
    free(handle);

    return true;
}

ssize_t socket_read(fd_t *fd, void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = fd->node->handle;
    socket_t *sock = handle->sock;

    if (!sock->peer && !sock->established && sock->recv_pos == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, buf, limit, 0, fd);
}

ssize_t socket_write(fd_t *fd, const void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = fd->node->handle;
    socket_t *sock = handle->sock;

    if (!sock->peer) {
        if (sock->type != 2 && sock->established) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -(EPIPE);
        }
        return -(ENOTCONN);
    }

    return unix_socket_send_to_peer(sock, sock->peer, buf, limit, 0, fd);
}

int unix_socket_pair(int type, int protocol, int *sv) {
    socket_t *sock1 = unix_socket_alloc();
    socket_t *sock2 = unix_socket_alloc();

    sock1->domain = 1;
    sock1->type = type & 0xF;
    sock1->protocol = protocol;

    sock2->domain = 1;
    sock2->type = type & 0xF;
    sock2->protocol = protocol;

    // 双向连接
    sock1->peer = sock2;
    sock2->peer = sock1;
    sock1->established = true;
    sock2->established = true;

    vfs_node_t node1 = unix_socket_create_node(sock1);
    vfs_node_t node2 = unix_socket_create_node(sock2);

    uint64_t flags = 0;
    if (type & O_NONBLOCK)
        flags |= O_NONBLOCK;

    int fd1 = -1, fd2 = -1;
    int ret = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL) {
                if (fd1 == -1)
                    fd1 = i;
                else {
                    fd2 = i;
                    break;
                }
            }
        }

        if (fd1 < 0 || fd2 < 0)
            break;

        fd_t *entry1 = malloc(sizeof(fd_t));
        fd_t *entry2 = malloc(sizeof(fd_t));
        if (!entry1 || !entry2) {
            free(entry1);
            free(entry2);
            ret = -ENOMEM;
            fd1 = fd2 = -1;
            break;
        }

        memset(entry1, 0, sizeof(fd_t));
        memset(entry2, 0, sizeof(fd_t));
        entry1->node = node1;
        entry1->offset = 0;
        entry1->flags = flags;
        entry1->close_on_exec = !!(type & O_CLOEXEC);
        entry2->node = node2;
        entry2->offset = 0;
        entry2->flags = flags;
        entry2->close_on_exec = !!(type & O_CLOEXEC);

        current_task->fd_info->fds[fd1] = entry1;
        current_task->fd_info->fds[fd2] = entry2;
        procfs_on_open_file(current_task, fd1);
        procfs_on_open_file(current_task, fd2);

        socket_handle_t *h1 = node1->handle;
        socket_handle_t *h2 = node2->handle;
        h1->fd = entry1;
        h2->fd = entry2;
        ret = 0;
    });

    if (ret < 0) {
        unix_socket_free(sock1);
        unix_socket_free(sock2);
        vfs_free(node1);
        vfs_free(node2);
        return ret;
    }

    sv[0] = fd1;
    sv[1] = fd2;

    return 0;
}

int unix_socket_getsockname(uint64_t fd, struct sockaddr_un *addr,
                            socklen_t *addrlen) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -(EBADF);

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    unix_socket_write_sockaddr(unix_socket_local_name(sock), addr, addrlen);

    return 0;
}

size_t unix_socket_getpeername(uint64_t fd, struct sockaddr_un *addr,
                               socklen_t *len) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (!sock->peer)
        return -ENOTCONN;

    unix_socket_write_sockaddr(unix_socket_local_name(sock->peer), addr, len);

    return 0;
}

size_t unix_socket_setsockopt(uint64_t fd, int level, int optname,
                              const void *optval, socklen_t optlen) {
    if (level != SOL_SOCKET)
        return -ENOPROTOOPT;

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    switch (optname) {
    case SO_REUSEADDR:
        if (optlen < sizeof(int))
            return -EINVAL;
        sock->reuseaddr = *(int *)optval;
        break;

    case SO_KEEPALIVE:
        if (optlen < sizeof(int))
            return -EINVAL;
        sock->keepalive = *(int *)optval;
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
            return -EINVAL;
        memcpy(&sock->sndtimeo, optval, sizeof(struct timeval));
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (optlen < sizeof(struct timeval))
            return -EINVAL;
        memcpy(&sock->rcvtimeo, optval, sizeof(struct timeval));
        break;

    case SO_BINDTODEVICE:
        if (optlen > IFNAMSIZ)
            return -EINVAL;
        strncpy(sock->bind_to_dev, optval, optlen);
        sock->bind_to_dev[IFNAMSIZ - 1] = '\0';
        break;

    case SO_LINGER:
        if (optlen < sizeof(struct linger))
            return -EINVAL;
        memcpy(&sock->linger_opt, optval, sizeof(struct linger));
        break;

    case SO_SNDBUF:
    case SO_RCVBUF:
        if (optlen < sizeof(int))
            return -EINVAL;
        {
            int new_size = *(int *)optval;
            if (new_size < BUFFER_SIZE)
                new_size = BUFFER_SIZE;

            mutex_lock(&sock->lock);
            void *newBuff = alloc_frames_bytes(new_size);
            memcpy(newBuff, sock->recv_buff, MIN(new_size, sock->recv_size));
            free_frames_bytes(sock->recv_buff, sock->recv_size);
            sock->recv_buff = newBuff;
            sock->recv_size = new_size;
            mutex_unlock(&sock->lock);
        }
        break;

    case SO_PASSCRED:
        if (optlen < sizeof(int))
            return -EINVAL;
        sock->passcred = *(int *)optval;
        break;

    case SO_PEERCRED:
        return -ENOPROTOOPT; // 只读

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t unix_socket_getsockopt(uint64_t fd, int level, int optname, void *optval,
                              socklen_t *optlen) {
    if (level != SOL_SOCKET)
        return -ENOPROTOOPT;

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    switch (optname) {
    case SO_ERROR:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = 0;
        *optlen = sizeof(int);
        break;

    case SO_REUSEADDR:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->reuseaddr;
        *optlen = sizeof(int);
        break;

    case SO_KEEPALIVE:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->keepalive;
        *optlen = sizeof(int);
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
            return -EINVAL;
        memcpy(optval, &sock->sndtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (*optlen < sizeof(struct timeval))
            return -EINVAL;
        memcpy(optval, &sock->rcvtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;

    case SO_BINDTODEVICE:
        if (*optlen < IFNAMSIZ)
            return -EINVAL;
        strncpy(optval, sock->bind_to_dev, IFNAMSIZ);
        *optlen = strlen(sock->bind_to_dev) + 1;
        break;

    case SO_PROTOCOL:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->protocol;
        *optlen = sizeof(int);
        break;

    case SO_DOMAIN:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->domain;
        *optlen = sizeof(int);
        break;

    case SO_LINGER:
        if (*optlen < sizeof(struct linger))
            return -EINVAL;
        memcpy(optval, &sock->linger_opt, sizeof(struct linger));
        *optlen = sizeof(struct linger);
        break;

    case SO_SNDBUF:
    case SO_RCVBUF:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->recv_size;
        *optlen = sizeof(int);
        break;

    case SO_PASSCRED:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->passcred;
        *optlen = sizeof(int);
        break;

    case SO_PEERCRED:
        if (!sock->peer)
            return -ENOTCONN;
        if (*optlen < sizeof(struct ucred))
            return -EINVAL;
        memcpy(optval, &sock->peer->cred, sizeof(struct ucred));
        *optlen = sizeof(struct ucred);
        break;

    case SO_ACCEPTCONN:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = (sock->connMax > 0) ? 1 : 0;
        *optlen = sizeof(int);
        break;

    case SO_TYPE:
        if (*optlen < sizeof(int))
            return -EINVAL;
        *(int *)optval = sock->type;
        *optlen = sizeof(int);
        break;

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

static int dummy() { return 0; }

socket_op_t socket_ops = {
    .shutdown = socket_shutdown,
    .accept = socket_accept,
    .listen = socket_listen,
    .getsockname = unix_socket_getsockname,
    .bind = socket_bind,
    .connect = socket_connect,
    .sendto = unix_socket_sendto,
    .recvfrom = unix_socket_recvfrom,
    .sendmsg = unix_socket_sendmsg,
    .recvmsg = unix_socket_recvmsg,
    .getpeername = unix_socket_getpeername,
    .getsockopt = unix_socket_getsockopt,
    .setsockopt = unix_socket_setsockopt,
};

static struct vfs_callback socket_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .remount = (vfs_remount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)socket_close,
    .read = (vfs_read_t)socket_read,
    .write = (vfs_write_t)socket_write,
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
    .ioctl = (vfs_ioctl_t)socket_ioctl,
    .poll = (vfs_poll_t)socket_poll,
    .resize = (vfs_resize_t)dummy,
    .free_handle = vfs_generic_free_handle,
};

fs_t sockfs = {
    .name = "sockfs",
    .magic = 0,
    .callback = &socket_callback,
    .flags = FS_FLAGS_HIDDEN | FS_FLAGS_VIRTUAL,
};

void socketfs_init() {
    unix_socket_fsid = vfs_regist(&sockfs);
    spin_init(&unix_socket_list_lock);
    memset(&first_unix_socket, 0, sizeof(socket_t));
    regist_socket(1, NULL, socket_socket);
    netlink_init();
}
