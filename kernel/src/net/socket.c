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
extern socket_op_t accept_ops;

vfs_node_t sockfs_root = NULL;

int sockfsfd_id = 0;

socket_t first_unix_socket;

socket_t sockets[MAX_SOCKETS];

int unix_socket_fsid = 0;
int unix_accept_fsid = 0;

char *unix_socket_addr_safe(const struct sockaddr_un *addr, size_t len) {
    size_t addrLen = len - sizeof(addr->sun_family);
    if (addrLen <= 0)
        return (void *)-(EINVAL);

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

vfs_node_t unix_socket_accept_create(unix_socket_pair_t *dir) {
    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_child_append(sockfs_root, buf, NULL);
    socknode->refcount++;
    socknode->type = file_socket;
    socknode->mode = 0700;

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    handle->op = &accept_ops;
    handle->sock = dir;

    socknode->fsid = unix_accept_fsid;
    socknode->handle = handle;

    return socknode;
}

#define MAX_PENDING_FILES_COUNT 64

unix_socket_pair_t *unix_socket_allocate_pair() {
    unix_socket_pair_t *pair = malloc(sizeof(unix_socket_pair_t));
    memset(pair, 0, sizeof(unix_socket_pair_t));
    pair->clientBuffSize = BUFFER_SIZE;
    pair->serverBuffSize = BUFFER_SIZE;
    pair->serverBuff = alloc_frames_bytes(pair->serverBuffSize);
    pair->clientBuff = alloc_frames_bytes(pair->clientBuffSize);
    pair->client_pending_files =
        malloc(MAX_PENDING_FILES_COUNT * sizeof(fd_t *));
    pair->server_pending_files =
        malloc(MAX_PENDING_FILES_COUNT * sizeof(fd_t *));
    memset(pair->client_pending_files, 0,
           MAX_PENDING_FILES_COUNT * sizeof(fd_t *));
    memset(pair->server_pending_files, 0,
           MAX_PENDING_FILES_COUNT * sizeof(fd_t *));
    memset(&pair->client_pending_cred, 0, sizeof(struct ucred));
    pair->has_client_pending_cred = false;
    memset(&pair->server_pending_cred, 0, sizeof(struct ucred));
    pair->has_server_pending_cred = true;
    pair->pending_fds_size = MAX_PENDING_FILES_COUNT;
    return pair;
}

void unix_socket_free_pair(unix_socket_pair_t *pair) {
    free_frames_bytes(pair->clientBuff, pair->clientBuffSize);
    free_frames_bytes(pair->serverBuff, pair->serverBuffSize);
    if (pair->filename)
        free(pair->filename);
    free(pair->client_pending_files);
    free(pair->server_pending_files);
    free(pair);
}

bool socket_accept_close(socket_handle_t *handle) {
    if (!handle)
        return true;

    unix_socket_pair_t *pair = handle->sock;
    pair->serverFds--;

    if (pair->serverFds == 0 && pair->clientFds == 0)
        unix_socket_free_pair(pair);

    return false;
}

bool socket_socket_close(socket_handle_t *socket_handle) {
    if (!socket_handle)
        return true;

    socket_t *unixSocket = socket_handle->sock;
    if (unixSocket->timesOpened >= 1) {
        unixSocket->timesOpened--;
    }
    if (unixSocket->pair) {
        unixSocket->pair->clientFds--;
        if (!unixSocket->pair->clientFds && !unixSocket->pair->serverFds)
            unix_socket_free_pair(unixSocket->pair);
    }
    if (unixSocket->timesOpened == 0) {
        socket_t *browse = &first_unix_socket;

        while (browse && browse->next != unixSocket) {
            browse = browse->next;
        }

        browse->next = unixSocket->next;
        free(unixSocket);
        free(socket_handle);

        return true;
    }

    return false;
}

size_t unix_socket_accept_recv_from(uint64_t fd, uint8_t *out, size_t limit,
                                    int flags, struct sockaddr_un *addr,
                                    uint32_t *len) {
    (void)addr;
    (void)len;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;
    while (true) {
        if (!pair->clientFds && pair->serverBuffPos == 0) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return 0;
        } else if ((current_task->fd_info->fds[fd]->flags & O_NONBLOCK ||
                    flags & MSG_DONTWAIT) &&
                   pair->serverBuffPos == 0) {
            return -(EWOULDBLOCK);
        } else if (pair->serverBuffPos > 0)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    size_t toCopy = MIN(limit, pair->serverBuffPos);
    memcpy(out, pair->serverBuff, toCopy);
    memmove(pair->serverBuff, &pair->serverBuff[toCopy],
            pair->serverBuffPos - toCopy);
    pair->serverBuffPos -= toCopy;

    spin_unlock(&pair->lock);

    return toCopy;
}

size_t unix_socket_accept_sendto(uint64_t fd, uint8_t *in, size_t limit,
                                 int flags, struct sockaddr_un *addr,
                                 uint32_t len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;

    if (limit > pair->clientBuffSize) {
        limit = pair->clientBuffSize;
    }

    while (true) {
        if (!pair->clientFds) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }

        if ((pair->clientBuffPos + limit) <= pair->clientBuffSize)
            break;

        if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK ||
            flags & MSG_DONTWAIT) {
            return -(EWOULDBLOCK);
        }

        arch_yield();
    }

    spin_lock(&pair->lock);

    limit = MIN(limit, pair->clientBuffSize);
    memcpy(&pair->clientBuff[pair->clientBuffPos], in, limit);
    pair->clientBuffPos += limit;

    spin_unlock(&pair->lock);

    return limit;
}

int socket_accept_poll(void *file, int events) {
    socket_handle_t *handle = file;
    unix_socket_pair_t *pair = handle->sock;
    if (!pair)
        return 0;

    spin_lock(&pair->lock);

    int revents = 0;

    if (!pair->clientFds)
        revents |= EPOLLHUP;

    if ((events & EPOLLOUT) && pair->clientFds &&
        pair->clientBuffPos < pair->clientBuffSize)
        revents |= EPOLLOUT;

    if ((events & EPOLLIN) && pair->serverBuffPos > 0)
        revents |= EPOLLIN;

    spin_unlock(&pair->lock);

    return revents;
}

int socket_socket(int domain, int type, int protocol) {
    // if (!(type & 1))
    // {
    //     return -ENOSYS;
    // }

    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);
    vfs_node_t socknode = vfs_node_alloc(sockfs_root, buf);
    socknode->type = file_socket;
    socknode->fsid = unix_socket_fsid;
    socknode->refcount++;
    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    socket_t *unix_socket = malloc(sizeof(socket_t));
    memset(unix_socket, 0, sizeof(socket_t));

    socket_t *head = &first_unix_socket;
    while (head->next) {
        head = head->next;
    }

    head->next = unix_socket;

    handle->sock = unix_socket;
    handle->op = &socket_ops;
    socknode->handle = handle;

    unix_socket->timesOpened = 1;
    unix_socket->domain = domain;
    unix_socket->type = type;
    unix_socket->protocol = protocol;

    if (unix_socket->type & 2) {
        unix_socket->dgramBuffPos = 0;
        unix_socket->dgramBuffSize = BUFFER_SIZE;
        unix_socket->dgramBuf = alloc_frames_bytes(unix_socket->dgramBuffSize);
    }

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        return -EMFILE;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = socknode;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = 0;
    procfs_on_open_file(current_task, i);

    handle->fd = current_task->fd_info->fds[i];

    return i;
}

int socket_bind(uint64_t fd, const struct sockaddr_un *addr,
                socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->bindAddr)
        return -(EINVAL);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;

    bool is_abstract = (addr->sun_path[0] == '\0');

    size_t safeLen = strlen(safe);
    socket_t *browse = &first_unix_socket;
    while (browse) {
        if (browse != sock && browse->bindAddr &&
            strlen(browse->bindAddr) == safeLen &&
            memcmp(safe, browse->bindAddr, safeLen) == 0)
            break;
        browse = browse->next;
    }

    if (browse) {
        free(safe);
        return -(EADDRINUSE);
    }

    if (!is_abstract) {
        vfs_node_t new_node = vfs_open(safe);
        if (new_node) {
            // free(safe);
            // return -(EADDRINUSE);
        } else {
            vfs_mknod(safe, S_IFSOCK | 0666, 0);
        }
    }

    sock->bindAddr = strdup(safe);
    free(safe);

    return 0;
}

int socket_listen(uint64_t fd, int backlog) {
    if (backlog == 0) // newer kernel behavior
        backlog = 16;
    if (backlog < 0)
        backlog = 128;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    // maybe do a typical array here
    sock->connMax = backlog;
    sock->backlog = calloc(sock->connMax, sizeof(unix_socket_pair_t *));
    return 0;
}

int socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen,
                  uint64_t flags) {
    if (addr && addrlen && *addrlen > 0) {
    }

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    while (true) {
        if (sock->connCurr > 0)
            break;
        if (current_task->fd_info->fds[fd]->flags & O_NONBLOCK) {
            sock->acceptWouldBlock = true;
            return -(EWOULDBLOCK);
        } else
            sock->acceptWouldBlock = false;

        arch_yield();
    }

    unix_socket_pair_t *pair = sock->backlog[0];
    pair->established = true;
    pair->serverFds++;
    pair->filename = strdup(sock->bindAddr);
    pair->cred.pid = current_task->pid;
    pair->cred.uid = current_task->uid;
    pair->cred.gid = current_task->gid;

    vfs_node_t acceptFd = unix_socket_accept_create(pair);
    sock->backlog[0] = NULL;
    memmove(sock->backlog, &sock->backlog[1],
            sock->connCurr * sizeof(unix_socket_pair_t *));
    sock->connCurr--;

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        return -EMFILE;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = acceptFd;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = flags;
    procfs_on_open_file(current_task, i);

    socket_handle_t *accept_handle = acceptFd->handle;
    accept_handle->fd = current_task->fd_info->fds[i];

    return i;
}

int socket_connect(uint64_t fd, const struct sockaddr_un *addr,
                   socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;

    if (sock->connMax != 0) // already ran listen()
        return -(ECONNREFUSED);

    if (sock->pair) // already ran connect()
        return -(EISCONN);

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;
    size_t safeLen = strlen(safe);

    socket_t *parent = &first_unix_socket;
    while (parent) {
        if (parent == sock) {
            parent = parent->next;
            continue;
        }

        if (parent->bindAddr && strlen(parent->bindAddr) == safeLen &&
            memcmp(safe, parent->bindAddr, safeLen) == 0)
            break;

        parent = parent->next;
    }
    free(safe);

    if (!parent)
        return -(ENOENT);

    if (parent->acceptWouldBlock &&
        (current_task->fd_info->fds[fd]->flags & O_NONBLOCK)) {
        return -(EINPROGRESS);
    }

    if (!parent->connMax) {
        return -(ECONNREFUSED);
    }

    if (parent->connCurr >= parent->connMax) {
        return -(ECONNREFUSED); // no slot
    }

    // Check not a udp socket
    if (!(sock->type & 2)) {
        if (!parent->backlog)
            return -(ECONNREFUSED); // no slot

        unix_socket_pair_t *pair = unix_socket_allocate_pair();
        sock->pair = pair;
        pair->clientFds = 1;
        parent->backlog[parent->connCurr] = pair;

        pair->peercred.pid = current_task->pid;
        pair->peercred.uid = current_task->uid;
        pair->peercred.gid = current_task->gid;
        pair->has_peercred = true;

        parent->connCurr++;

        while (!pair->established) {
            arch_yield();
        }
    }

    return 0;
}

size_t unix_socket_recv_from(uint64_t fd, uint8_t *out, size_t limit, int flags,
                             struct sockaddr_un *addr, uint32_t *len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *socket = handle->sock;

    // if (socket->type & 2) {
    //     uint32_t addrlen;
    //     if (copy_from_user(&addrlen, len, sizeof(uint32_t)))
    //         return (size_t)-EFAULT;
    //     char *safe = unix_socket_addr_safe(addr, addrlen);
    //     if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
    //         return (uint64_t)safe;
    //     size_t safeLen = strlen(safe);

    //     socket_t *parent = &first_unix_socket;
    //     while (parent) {
    //         if (parent == socket) {
    //             parent = parent->next;
    //             continue;
    //         }

    //         if (parent->bindAddr && strlen(parent->bindAddr) == safeLen &&
    //             memcmp(safe, parent->bindAddr, safeLen) == 0)
    //             break;

    //         parent = parent->next;
    //     }
    //     free(safe);

    //     if (!parent)
    //         return -(ENOENT);

    //     if (flags & MSG_PEEK)
    //         return parent->dgramBuffPos;

    //     while (true) {
    //         if ((current_task->fd_info->fds[fd]->flags & O_NONBLOCK ||
    //              flags & MSG_DONTWAIT) &&
    //             parent->dgramBuffPos == 0) {
    //             return -(EWOULDBLOCK);
    //         } else if (parent->dgramBuffPos > 0)
    //             break;

    //         arch_yield();
    //     }

    //     spin_lock(&parent->dgram_lock);

    //     size_t toCopy = MIN(limit, parent->dgramBuffPos);
    //     memcpy(out, parent->dgramBuf, toCopy);
    //     memmove(parent->dgramBuf, &parent->dgramBuf[toCopy],
    //             parent->dgramBuffPos - toCopy);
    //     parent->dgramBuffPos -= toCopy;

    //     spin_unlock(&parent->dgram_lock);

    //     return toCopy;
    // }

    unix_socket_pair_t *pair = socket->pair;
    if (!pair) {
        return -(ENOTCONN);
    }

    if (flags & MSG_PEEK)
        return pair->clientBuffPos;

    while (true) {
        if (!pair->serverFds && pair->clientBuffPos == 0) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return 0;
        } else if ((current_task->fd_info->fds[fd]->flags & O_NONBLOCK ||
                    flags & MSG_DONTWAIT) &&
                   pair->clientBuffPos == 0) {
            return -(EWOULDBLOCK);
        } else if (pair->clientBuffPos > 0)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    size_t toCopy = MIN(limit, pair->clientBuffPos);
    memcpy(out, pair->clientBuff, toCopy);
    memmove(pair->clientBuff, &pair->clientBuff[toCopy],
            pair->clientBuffPos - toCopy);
    pair->clientBuffPos -= toCopy;

    spin_unlock(&pair->lock);

    return toCopy;
}

size_t unix_socket_send_to(uint64_t fd, uint8_t *in, size_t limit, int flags,
                           struct sockaddr_un *addr, uint32_t len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *socket = handle->sock;

    // if (socket->type & 2) {
    //     char *safe = unix_socket_addr_safe(addr, len);
    //     if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
    //         return (uint64_t)safe;
    //     size_t safeLen = strlen(safe);

    //     socket_t *parent = &first_unix_socket;
    //     while (parent) {
    //         if (parent == socket) {
    //             parent = parent->next;
    //             continue;
    //         }

    //         if (parent->bindAddr && strlen(parent->bindAddr) == safeLen &&
    //             memcmp(safe, parent->bindAddr, safeLen) == 0)
    //             break;

    //         parent = parent->next;
    //     }
    //     free(safe);

    //     if (!parent)
    //         return -(ENOENT);

    //     spin_lock(&parent->dgram_lock);
    //     limit = MIN(limit, parent->dgramBuffSize);
    //     memcpy(&parent->dgramBuf[parent->dgramBuffPos], in, limit);
    //     parent->dgramBuffPos += limit;
    //     spin_unlock(&parent->dgram_lock);

    //     return limit;
    // }

    unix_socket_pair_t *pair = socket->pair;
    if (!pair) {
        return -(ENOTCONN);
    }
    if (limit > pair->serverBuffSize) {
        limit = pair->serverBuffSize;
    }

    while (true) {
        if (!pair->serverFds) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        } else if ((current_task->fd_info->fds[fd]->flags & O_NONBLOCK ||
                    flags & MSG_DONTWAIT) &&
                   (pair->serverBuffPos + limit) > pair->serverBuffSize) {
            return -(EWOULDBLOCK);
        } else if ((pair->serverBuffPos + limit) <= pair->serverBuffSize)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    limit = MIN(limit, pair->serverBuffSize);
    memcpy(&pair->serverBuff[pair->serverBuffPos], in, limit);
    pair->serverBuffPos += limit;

    spin_unlock(&pair->lock);

    return limit;
}

size_t unix_socket_recv_msg(uint64_t fd, struct msghdr *msg, int flags) {
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);

    // 初始化消息标志
    msg->msg_flags = 0;

    while (
        !noblock && !(current_task->fd_info->fds[fd]->flags & O_NONBLOCK) &&
        !(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN)) {
        arch_yield();
    }

    if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN)) {
        return (size_t)-EWOULDBLOCK;
    }

    int len_total = 0;

    // 使用正确的类型转换
    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        len_total += curr->len;
    }

    char *buffer = malloc(len_total);

    cnt = unix_socket_recv_from(fd, (uint8_t *)buffer, len_total,
                                noblock ? MSG_DONTWAIT : 0, NULL, 0);
    if ((int64_t)cnt < 0) {
        free(buffer);
        return cnt;
    }

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
        socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
        socket_t *sock = handle->sock;
        unix_socket_pair_t *pair = sock->pair;
        if (!pair) {
            return (size_t)-ENOTCONN;
        }

        size_t controllen_used = 0;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        spin_lock(&pair->lock);

        // 处理SCM_RIGHTS（文件描述符）
        bool has_pending_fds = false;
        for (int i = 0; i < MAX_PENDING_FILES_COUNT; i++) {
            if (pair->client_pending_files[i] != NULL) {
                has_pending_fds = true;
                break;
            }
        }

        if (has_pending_fds && cmsg) {
            // 计算可以接收的文件描述符数量
            size_t space_left = msg->msg_controllen - controllen_used;
            size_t max_fds = 0;

            if (space_left >= CMSG_SPACE(sizeof(int))) {
                max_fds = (space_left - sizeof(struct cmsghdr)) / sizeof(int);

                if (max_fds > 0) {
                    cmsg->cmsg_level = SOL_SOCKET;
                    cmsg->cmsg_type = SCM_RIGHTS;

                    int *fds_out = (int *)CMSG_DATA(cmsg);
                    size_t received_fds = 0;

                    for (int i = 0;
                         i < MAX_PENDING_FILES_COUNT && received_fds < max_fds;
                         i++) {
                        if (pair->client_pending_files[i] == NULL) {
                            continue;
                        }

                        // 查找可用的文件描述符
                        int new_fd = -1;
                        for (int fd_idx = 0; fd_idx < MAX_FD_NUM; fd_idx++) {
                            if (current_task->fd_info->fds[fd_idx] == NULL) {
                                new_fd = fd_idx;
                                break;
                            }
                        }

                        if (new_fd == -1) {
                            // 没有可用的文件描述符，设置截断标志
                            msg->msg_flags |= MSG_CTRUNC;
                            break;
                        }

                        // 分配并复制文件描述符
                        current_task->fd_info->fds[new_fd] =
                            malloc(sizeof(fd_t));
                        if (!current_task->fd_info->fds[new_fd]) {
                            msg->msg_flags |= MSG_CTRUNC;
                            break;
                        }

                        memcpy(current_task->fd_info->fds[new_fd],
                               pair->client_pending_files[i], sizeof(fd_t));
                        free(pair->client_pending_files[i]);
                        pair->client_pending_files[i] = NULL;

                        fds_out[received_fds] = new_fd;
                        procfs_on_open_file(current_task, new_fd);
                        received_fds++;
                    }

                    if (received_fds > 0) {
                        cmsg->cmsg_len = CMSG_LEN(received_fds * sizeof(int));
                        controllen_used +=
                            CMSG_SPACE(received_fds * sizeof(int));

                        // 移动到下一个控制消息头
                        cmsg = CMSG_NXTHDR(msg, cmsg);
                    }
                }
            } else {
                // 空间不足，设置截断标志
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        // 处理SCM_CREDENTIALS（凭据）
        bool should_send_cred =
            (pair->passcred || sock->passcred || pair->has_client_pending_cred);
        if (should_send_cred && cmsg) {
            size_t space_left = msg->msg_controllen - controllen_used;

            if (space_left >= CMSG_SPACE(sizeof(struct ucred))) {
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));

                struct ucred *cred_out = (struct ucred *)CMSG_DATA(cmsg);

                if (pair->has_client_pending_cred) {
                    memcpy(cred_out, &pair->client_pending_cred,
                           sizeof(struct ucred));
                    pair->has_client_pending_cred = false;
                } else {
                    // 使用对端凭据
                    memcpy(cred_out, &pair->peercred, sizeof(struct ucred));
                }

                controllen_used += CMSG_SPACE(sizeof(struct ucred));
            } else {
                // 空间不足，设置截断标志
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        spin_unlock(&pair->lock);

        msg->msg_controllen = controllen_used;
    } else {
        msg->msg_controllen = 0;
    }

    return cnt;
}

size_t unix_socket_send_msg(uint64_t fd, const struct msghdr *msg, int flags) {
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);

    if (msg->msg_control && msg->msg_controllen > 0) {
        socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
        socket_t *socket = handle->sock;
        unix_socket_pair_t *pair = socket->pair;
        if (!pair) {
            return (size_t)-ENOTCONN;
        }

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        spin_lock(&pair->lock);

        for (; cmsg != NULL; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET) {
                if (cmsg->cmsg_type == SCM_RIGHTS) {
                    int *fds = (int *)CMSG_DATA(cmsg);
                    int num_fds =
                        (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

                    for (int i = 0; i < num_fds; i++) {
                        // 查找可用的pending槽位
                        for (int j = 0; j < MAX_PENDING_FILES_COUNT; j++) {
                            if (pair->client_pending_files[j] == NULL) {
                                pair->client_pending_files[j] =
                                    malloc(sizeof(fd_t));
                                if (!pair->client_pending_files[j]) {
                                    spin_unlock(&pair->lock);
                                    return (size_t)-ENOMEM;
                                }

                                if (!current_task->fd_info->fds[fds[i]]) {
                                    free(pair->client_pending_files[j]);
                                    pair->client_pending_files[j] = NULL;
                                    continue;
                                }

                                memcpy(pair->client_pending_files[j],
                                       current_task->fd_info->fds[fds[i]],
                                       sizeof(fd_t));
                                current_task->fd_info->fds[fds[i]]
                                    ->node->refcount++;
                                break;
                            }
                        }
                    }
                } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
                    if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct ucred))) {
                        spin_unlock(&pair->lock);
                        return (size_t)-EINVAL;
                    }

                    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);

                    // 验证凭据（非root用户只能发送自己的凭据）
                    if (current_task->euid != 0) {
                        if (cred->pid != current_task->pid ||
                            cred->uid != current_task->uid ||
                            cred->gid != current_task->gid) {
                            spin_unlock(&pair->lock);
                            return (size_t)-EPERM;
                        }
                    }

                    memcpy(&pair->client_pending_cred, cred,
                           sizeof(struct ucred));
                    pair->has_client_pending_cred = true;
                }
            }
        }

        spin_unlock(&pair->lock);
    }

    // 发送数据部分
    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &((struct iovec *)msg->msg_iov)[i];

        size_t singleCnt = unix_socket_send_to(
            fd, curr->iov_base, curr->len, noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0) {
            return singleCnt;
        }

        cnt += singleCnt;
    }

    return cnt;
}

size_t unix_socket_accept_recv_msg(uint64_t fd, struct msghdr *msg, int flags) {
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);

    // 初始化消息标志
    msg->msg_flags = 0;

    while (
        !noblock && !(current_task->fd_info->fds[fd]->flags & O_NONBLOCK) &&
        !(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN)) {
        arch_yield();
    }

    if (!(vfs_poll(current_task->fd_info->fds[fd]->node, EPOLLIN) & EPOLLIN)) {
        return (size_t)-EWOULDBLOCK;
    }

    int len_total = 0;

    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &msg->msg_iov[i];
        len_total += curr->len;
    }

    char *buffer = malloc(len_total);

    cnt = unix_socket_accept_recv_from(fd, (uint8_t *)buffer, len_total,
                                       noblock ? MSG_DONTWAIT : 0, NULL, 0);
    if ((int64_t)cnt < 0) {
        free(buffer);
        return cnt;
    }

    char *b = buffer;
    uint32_t remain = cnt;

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
        socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
        unix_socket_pair_t *pair = handle->sock;

        size_t controllen_used = 0;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        spin_lock(&pair->lock);

        // 处理SCM_RIGHTS（文件描述符）
        bool has_pending_fds = false;
        for (int i = 0; i < MAX_PENDING_FILES_COUNT; i++) {
            if (pair->server_pending_files[i] != NULL) {
                has_pending_fds = true;
                break;
            }
        }

        if (has_pending_fds && cmsg) {
            size_t space_left = msg->msg_controllen - controllen_used;
            size_t max_fds = 0;

            if (space_left >= CMSG_SPACE(sizeof(int))) {
                max_fds = (space_left - sizeof(struct cmsghdr)) / sizeof(int);

                if (max_fds > 0) {
                    cmsg->cmsg_level = SOL_SOCKET;
                    cmsg->cmsg_type = SCM_RIGHTS;

                    int *fds_out = (int *)CMSG_DATA(cmsg);
                    size_t received_fds = 0;

                    for (int i = 0;
                         i < MAX_PENDING_FILES_COUNT && received_fds < max_fds;
                         i++) {
                        if (pair->server_pending_files[i] == NULL) {
                            continue;
                        }

                        int new_fd = -1;
                        for (int fd_idx = 0; fd_idx < MAX_FD_NUM; fd_idx++) {
                            if (current_task->fd_info->fds[fd_idx] == NULL) {
                                new_fd = fd_idx;
                                break;
                            }
                        }

                        if (new_fd == -1) {
                            msg->msg_flags |= MSG_CTRUNC;
                            break;
                        }

                        current_task->fd_info->fds[new_fd] =
                            malloc(sizeof(fd_t));
                        if (!current_task->fd_info->fds[new_fd]) {
                            msg->msg_flags |= MSG_CTRUNC;
                            break;
                        }

                        memcpy(current_task->fd_info->fds[new_fd],
                               pair->server_pending_files[i], sizeof(fd_t));
                        free(pair->server_pending_files[i]);
                        pair->server_pending_files[i] = NULL;

                        fds_out[received_fds] = new_fd;
                        procfs_on_open_file(current_task, new_fd);
                        received_fds++;
                    }

                    if (received_fds > 0) {
                        cmsg->cmsg_len = CMSG_LEN(received_fds * sizeof(int));
                        controllen_used +=
                            CMSG_SPACE(received_fds * sizeof(int));
                        cmsg = CMSG_NXTHDR(msg, cmsg);
                    }
                }
            } else {
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        // 处理SCM_CREDENTIALS（凭据）
        bool should_send_cred =
            (pair->passcred || pair->has_server_pending_cred);
        if (should_send_cred && cmsg) {
            size_t space_left = msg->msg_controllen - controllen_used;

            if (space_left >= CMSG_SPACE(sizeof(struct ucred))) {
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));

                struct ucred *cred_out = (struct ucred *)CMSG_DATA(cmsg);

                if (pair->has_server_pending_cred) {
                    memcpy(cred_out, &pair->server_pending_cred,
                           sizeof(struct ucred));
                    pair->has_server_pending_cred = false;
                } else {
                    memcpy(cred_out, &pair->cred, sizeof(struct ucred));
                }

                controllen_used += CMSG_SPACE(sizeof(struct ucred));
            } else {
                msg->msg_flags |= MSG_CTRUNC;
            }
        }

        spin_unlock(&pair->lock);

        msg->msg_controllen = controllen_used;
    } else {
        msg->msg_controllen = 0;
    }

    return cnt;
}

size_t unix_socket_accept_send_msg(uint64_t fd, const struct msghdr *msg,
                                   int flags) {
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);

    if (msg->msg_control && msg->msg_controllen > 0) {
        socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
        unix_socket_pair_t *pair = handle->sock;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
        if (!cmsg) {
            goto no_cmsg;
        }

        spin_lock(&pair->lock);

        for (; cmsg != NULL; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET) {
                if (cmsg->cmsg_type == SCM_RIGHTS) {
                    int *fds = (int *)CMSG_DATA(cmsg);
                    int num_fds =
                        (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

                    for (int i = 0; i < num_fds; i++) {
                        for (int j = 0; j < MAX_PENDING_FILES_COUNT; j++) {
                            if (pair->server_pending_files[j] == NULL) {
                                pair->server_pending_files[j] =
                                    malloc(sizeof(fd_t));
                                if (!pair->server_pending_files[j]) {
                                    spin_unlock(&pair->lock);
                                    return (size_t)-ENOMEM;
                                }

                                if (!current_task->fd_info->fds[fds[i]]) {
                                    free(pair->server_pending_files[j]);
                                    pair->server_pending_files[j] = NULL;
                                    continue;
                                }

                                memcpy(pair->server_pending_files[j],
                                       current_task->fd_info->fds[fds[i]],
                                       sizeof(fd_t));
                                current_task->fd_info->fds[fds[i]]
                                    ->node->refcount++;
                                break;
                            }
                        }
                    }
                } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
                    if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct ucred))) {
                        spin_unlock(&pair->lock);
                        return (size_t)-EINVAL;
                    }

                    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);

                    if (current_task->euid != 0) {
                        if (cred->pid != current_task->pid ||
                            cred->uid != current_task->uid ||
                            cred->gid != current_task->gid) {
                            spin_unlock(&pair->lock);
                            return (size_t)-EPERM;
                        }
                    }

                    memcpy(&pair->server_pending_cred, cred,
                           sizeof(struct ucred));
                    pair->has_server_pending_cred = true;
                }
            }
        }

        spin_unlock(&pair->lock);
    }

no_cmsg:
    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &((struct iovec *)msg->msg_iov)[i];

        size_t singleCnt = unix_socket_accept_sendto(
            fd, curr->iov_base, curr->len, noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0) {
            return singleCnt;
        }

        cnt += singleCnt;
    }

    return cnt;
}

int unix_socket_pair(int type, int protocol, int *sv) {
    size_t sock1 = socket_socket(1, type, protocol);
    if ((int64_t)(sock1) < 0)
        return sock1;

    vfs_node_t sock1Fd = current_task->fd_info->fds[sock1]->node;

    unix_socket_pair_t *pair = unix_socket_allocate_pair();
    pair->clientFds = 1;
    pair->serverFds = 1;

    socket_handle_t *handle = sock1Fd->handle;
    socket_t *sock = handle->sock;
    sock->domain = 1;
    sock->type = type;
    sock->protocol = protocol;
    sock->pair = pair;
    sock->connMax = 0;
    handle->sock = sock;

    vfs_node_t sock2Fd = unix_socket_accept_create(pair);

    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        unix_socket_free_pair(pair);
        sys_close(sock1);
        vfs_free(sock2Fd);
        return -EMFILE;
    }

    pair->peercred.pid = current_task->pid;
    pair->peercred.uid = current_task->uid;
    pair->peercred.gid = current_task->gid;
    pair->has_peercred = true;

    socket_handle_t *new_handle = sock2Fd->handle;

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = sock2Fd;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = 0;
    procfs_on_open_file(current_task, i);

    new_handle->fd = current_task->fd_info->fds[i];

    // finish it off
    sv[0] = sock1;
    sv[1] = i;

    return 0;
}

int socket_socket_poll(void *file, int events) {
    socket_handle_t *handler = file;
    socket_t *socket = handler->sock;
    int revents = 0;

    if (socket->connMax > 0) {
        // listen()
        if (socket->connCurr < socket->connMax) // can connect()
            revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
        if (socket->connCurr > 0) // can accept()
            revents |= (events & EPOLLIN) ? EPOLLIN : 0;
    } else if (socket->pair) {
        // connect()
        unix_socket_pair_t *pair = socket->pair;
        spin_lock(&pair->lock);
        if (!pair->serverFds)
            revents |= EPOLLHUP;

        if ((events & EPOLLOUT) && pair->serverFds &&
            pair->serverBuffPos < pair->serverBuffSize)
            revents |= EPOLLOUT;

        if ((events & EPOLLIN) && pair->clientBuffPos > 0)
            revents |= EPOLLIN;
        spin_unlock(&pair->lock);
    } else {
        revents |= EPOLLHUP;
    }

    return revents;
}

size_t unix_socket_setsockopt(uint64_t fd, int level, int optname,
                              const void *optval, socklen_t optlen) {
    if (level != SOL_SOCKET) {
        return -ENOPROTOOPT;
    }

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;
    unix_socket_pair_t *pair = sock->pair;

    switch (optname) {
    case SO_REUSEADDR:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            pair->reuseaddr = *(int *)optval;
        break;

    case SO_KEEPALIVE:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            pair->keepalive = *(int *)optval;
        else
            return -ENOTCONN;
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(&pair->sndtimeo, optval, sizeof(struct timeval));
        else
            return -ENOTCONN;
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(&pair->rcvtimeo, optval, sizeof(struct timeval));
        else
            return -ENOTCONN;
        break;

    case SO_BINDTODEVICE:
        if (optlen > IFNAMSIZ) {
            return -EINVAL;
        }
        if (pair) {
            strncpy(pair->bind_to_dev, optval, optlen);
            pair->bind_to_dev[IFNAMSIZ - 1] = '\0';
        } else {
            return -ENOTCONN;
        }
        break;

    case SO_LINGER:
        if (optlen < sizeof(struct linger)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(&pair->linger_opt, optval, sizeof(struct linger));
        else
            return -ENOTCONN;
        break;

    case SO_SNDBUF:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair) {
            int new_size = *(int *)optval;
            if (new_size < BUFFER_SIZE) {
                new_size = BUFFER_SIZE;
            }
            spin_lock(&pair->lock);
            void *newBuff = alloc_frames_bytes(new_size);
            memcpy(newBuff, pair->serverBuff,
                   MIN(new_size, pair->serverBuffSize));
            free_frames_bytes(pair->serverBuff, pair->serverBuffSize);
            pair->serverBuff = newBuff;
            pair->serverBuffSize = new_size;
            spin_unlock(&pair->lock);
        } else {
            return -ENOTCONN;
        }
        break;

    case SO_RCVBUF:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair) {
            int new_size = *(int *)optval;
            if (new_size < BUFFER_SIZE) {
                new_size = BUFFER_SIZE;
            }
            spin_lock(&pair->lock);
            void *newBuff = alloc_frames_bytes(new_size);
            memcpy(newBuff, pair->clientBuff,
                   MIN(new_size, pair->clientBuffSize));
            free_frames_bytes(pair->clientBuff, pair->clientBuffSize);
            pair->clientBuff = newBuff;
            pair->clientBuffSize = new_size;
            spin_unlock(&pair->lock);
        } else {
            return -ENOTCONN;
        }
        break;

    case SO_PASSCRED:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        // SO_PASSCRED 可以在连接前后设置
        sock->passcred = *(int *)optval;
        if (pair)
            pair->passcred = *(int *)optval;
        break;

    case SO_PEERCRED:
        // SO_PEERCRED 是只读的
        return -ENOPROTOOPT;

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t unix_socket_getsockopt(uint64_t fd, int level, int optname,
                              const void *optval, socklen_t *optlen) {
    if (level != SOL_SOCKET) {
        return -ENOPROTOOPT;
    }

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *sock = handle->sock;
    unix_socket_pair_t *pair = sock->pair;

    switch (optname) {
    case SO_REUSEADDR:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            *(int *)optval = pair->reuseaddr;
        *optlen = sizeof(int);
        break;

    case SO_KEEPALIVE:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            *(int *)optval = pair->keepalive;
        else
            return -ENOTCONN;
        *optlen = sizeof(int);
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (*optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(optval, &pair->sndtimeo, sizeof(struct timeval));
        else
            return -ENOTCONN;

        *optlen = sizeof(struct timeval);
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (*optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(optval, &pair->rcvtimeo, sizeof(struct timeval));
        else
            return -ENOTCONN;
        *optlen = sizeof(struct timeval);
        break;

    case SO_BINDTODEVICE:
        if (*optlen < IFNAMSIZ) {
            return -EINVAL;
        }
        if (pair) {
            strncpy(optval, pair->bind_to_dev, IFNAMSIZ);
            *optlen = strlen(pair->bind_to_dev) + 1;
        } else {
            return -ENOTCONN;
        }
        break;

    case SO_PROTOCOL:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = sock->protocol;
        *optlen = sizeof(int);
        break;

    case SO_DOMAIN:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = sock->domain;
        *optlen = sizeof(int);
        break;

    case SO_LINGER:
        if (*optlen < sizeof(struct linger)) {
            return -EINVAL;
        }
        if (pair)
            memcpy(optval, &pair->linger_opt, sizeof(struct linger));
        else
            return -ENOTCONN;
        *optlen = sizeof(struct linger);
        break;

    case SO_SNDBUF:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            *(int *)optval = pair->serverBuffSize;
        else
            return -ENOTCONN;
        *optlen = sizeof(int);
        break;

    case SO_RCVBUF:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        if (pair)
            *(int *)optval = pair->clientBuffSize;
        else
            return -ENOTCONN;
        *optlen = sizeof(int);
        break;

    case SO_PASSCRED:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        // 返回当前 passcred 设置
        if (pair)
            *(int *)optval = pair->passcred;
        *optlen = sizeof(int);
        break;

    case SO_PEERCRED:
        // SO_PEERCRED 需要已连接
        if (!pair) {
            return -ENOTCONN;
        }
        if (!pair->has_peercred) {
            return -ENODATA;
        }
        if (*optlen < sizeof(struct ucred)) {
            return -EINVAL;
        }
        // 客户端获取的是服务端的凭据
        memcpy(optval, &pair->cred, sizeof(struct ucred));
        *optlen = sizeof(struct ucred);
        break;

    case SO_ACCEPTCONN:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = (sock->connMax > 0) ? 1 : 0;
        *optlen = sizeof(int);
        break;

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t unix_socket_accept_setsockopt(uint64_t fd, int level, int optname,
                                     const void *optval, socklen_t optlen) {
    if (level != SOL_SOCKET) {
        return -ENOPROTOOPT;
    }

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;

    if (!pair)
        return (size_t)-ENOTCONN;

    switch (optname) {
    case SO_REUSEADDR:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        pair->reuseaddr = *(int *)optval;
        break;

    case SO_KEEPALIVE:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        pair->keepalive = *(int *)optval;
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        memcpy(&pair->sndtimeo, optval, sizeof(struct timeval));
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        memcpy(&pair->rcvtimeo, optval, sizeof(struct timeval));
        break;

    case SO_BINDTODEVICE:
        if (optlen > IFNAMSIZ) {
            return -EINVAL;
        }
        strncpy(pair->bind_to_dev, optval, optlen);
        pair->bind_to_dev[IFNAMSIZ - 1] = '\0';
        break;

    case SO_LINGER:
        if (optlen < sizeof(struct linger)) {
            return -EINVAL;
        }
        memcpy(&pair->linger_opt, optval, sizeof(struct linger));
        break;

    case SO_SNDBUF:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        {
            int new_size = *(int *)optval;
            if (new_size < BUFFER_SIZE) {
                new_size = BUFFER_SIZE;
            }
            spin_lock(&pair->lock);
            void *newBuff = alloc_frames_bytes(new_size);
            memcpy(newBuff, pair->clientBuff,
                   MIN(new_size, pair->clientBuffSize));
            free_frames_bytes(pair->clientBuff, pair->clientBuffSize);
            pair->clientBuff = newBuff;
            pair->clientBuffSize = new_size;
            spin_unlock(&pair->lock);
        }
        break;

    case SO_RCVBUF:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        {
            int new_size = *(int *)optval;
            if (new_size < BUFFER_SIZE) {
                new_size = BUFFER_SIZE;
            }
            spin_lock(&pair->lock);
            void *newBuff = alloc_frames_bytes(new_size);
            memcpy(newBuff, pair->serverBuff,
                   MIN(new_size, pair->serverBuffSize));
            free_frames_bytes(pair->serverBuff, pair->serverBuffSize);
            pair->serverBuff = newBuff;
            pair->serverBuffSize = new_size;
            spin_unlock(&pair->lock);
        }
        break;

    case SO_PASSCRED:
        if (optlen < sizeof(int)) {
            return -EINVAL;
        }
        pair->passcred = *(int *)optval;
        break;

    case SO_PEERCRED:
        // SO_PEERCRED 是只读的
        return -ENOPROTOOPT;

    case SO_ATTACH_FILTER: {
        struct sock_fprog fprog;
        if (optlen < sizeof(fprog)) {
            return -EINVAL;
        }
        memcpy(&fprog, optval, sizeof(fprog));
        if (fprog.len > 64 || fprog.len == 0) {
            return -EINVAL;
        }
        spin_lock(&pair->lock);
        if (pair->filter)
            free(pair->filter);
        pair->filter = malloc(sizeof(struct sock_filter) * fprog.len);
        memcpy(pair->filter, fprog.filter,
               sizeof(struct sock_filter) * fprog.len);
        pair->filter_len = fprog.len;
        spin_unlock(&pair->lock);
        break;
    }

    case SO_DETACH_FILTER:
        spin_lock(&pair->lock);
        if (pair->filter) {
            free(pair->filter);
            pair->filter = NULL;
            pair->filter_len = 0;
        }
        spin_unlock(&pair->lock);
        break;

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

size_t unix_socket_accept_getsockopt(uint64_t fd, int level, int optname,
                                     const void *optval, socklen_t *optlen) {
    if (level != SOL_SOCKET) {
        return -ENOPROTOOPT;
    }

    if (!current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;

    if (!pair)
        return (size_t)-ENOTCONN;

    switch (optname) {
    case SO_REUSEADDR:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = pair->reuseaddr;
        *optlen = sizeof(int);
        break;

    case SO_KEEPALIVE:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = pair->keepalive;
        *optlen = sizeof(int);
        break;

    case SO_SNDTIMEO_OLD:
    case SO_SNDTIMEO_NEW:
        if (*optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        memcpy(optval, &pair->sndtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;

    case SO_RCVTIMEO_OLD:
    case SO_RCVTIMEO_NEW:
        if (*optlen < sizeof(struct timeval)) {
            return -EINVAL;
        }
        memcpy(optval, &pair->rcvtimeo, sizeof(struct timeval));
        *optlen = sizeof(struct timeval);
        break;

    case SO_BINDTODEVICE:
        if (*optlen < IFNAMSIZ) {
            return -EINVAL;
        }
        strncpy(optval, pair->bind_to_dev, IFNAMSIZ);
        *optlen = strlen(pair->bind_to_dev) + 1;
        break;

    case SO_LINGER:
        if (*optlen < sizeof(struct linger)) {
            return -EINVAL;
        }
        memcpy(optval, &pair->linger_opt, sizeof(struct linger));
        *optlen = sizeof(struct linger);
        break;

    case SO_SNDBUF:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = pair->clientBuffSize;
        *optlen = sizeof(int);
        break;

    case SO_RCVBUF:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = pair->serverBuffSize;
        *optlen = sizeof(int);
        break;

    case SO_PASSCRED:
        if (*optlen < sizeof(int)) {
            return -EINVAL;
        }
        *(int *)optval = pair->passcred;
        *optlen = sizeof(int);
        break;

    case SO_PEERCRED:
        if (!pair->has_peercred) {
            return -ENODATA;
        }
        if (*optlen < sizeof(struct ucred)) {
            return -EINVAL;
        }
        // 服务端获取的是客户端的凭据
        memcpy(optval, &pair->peercred, sizeof(struct ucred));
        *optlen = sizeof(struct ucred);
        break;

    case SO_ATTACH_FILTER:
        if (*optlen < sizeof(struct sock_fprog)) {
            return -EINVAL;
        }
        {
            struct sock_fprog fprog = {.len = pair->filter_len,
                                       .filter = pair->filter};
            memcpy(optval, &fprog, sizeof(fprog));
        }
        *optlen = sizeof(struct sock_fprog);
        break;

    default:
        return -ENOPROTOOPT;
    }

    return 0;
}

static int dummy() { return 0; }

size_t unix_socket_getpeername(uint64_t fd, struct sockaddr_un *addr,
                               socklen_t *len) {
    if (fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *socket = handle->sock;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);

    size_t actualLen = sizeof(addr->sun_family) + strlen(pair->filename);
    int toCopy = MIN(*len, actualLen);
    if (toCopy < sizeof(addr->sun_family))
        return -(EINVAL);
    addr->sun_family = 1;
    if (pair->filename[0] == '@') {
        memcpy(addr->sun_path, pair->filename + 1,
               toCopy - sizeof(addr->sun_family) - 1);
        // addr->sun_path[0] = '\0';
        *len = toCopy - 1;
    } else {
        memcpy(addr->sun_path, pair->filename,
               toCopy - sizeof(addr->sun_family));
        *len = toCopy;
    }
    return 0;
}

size_t unix_socket_accept_getpeername(uint64_t fd, struct sockaddr_un *addr,
                                      socklen_t *len) {
    if (fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;

    size_t actualLen = sizeof(addr->sun_family) + strlen(pair->filename);
    int toCopy = MIN(*len, actualLen);
    if (toCopy < sizeof(addr->sun_family))
        return -(EINVAL);
    addr->sun_family = 1;
    if (pair->filename[0] == '@') {
        memcpy(addr->sun_path, pair->filename + 1,
               toCopy - sizeof(addr->sun_family) - 1);
        // addr->sun_path[0] = '\0';
        *len = toCopy - 1;
    } else {
        memcpy(addr->sun_path, pair->filename,
               toCopy - sizeof(addr->sun_family));
        *len = toCopy;
    }
    return 0;
}

int unix_socket_getsockname(uint64_t fd, struct sockaddr_un *addr,
                            socklen_t *addrlen) {
    if (fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -(EBADF);

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    socket_t *socket = handle->sock;
    unix_socket_pair_t *pair = socket->pair;
    if (!pair)
        return -(ENOTCONN);

    addr->sun_family = 1;
    strcpy(addr->sun_path, pair->filename);
    *addrlen = sizeof(addr->sun_family) + strlen(pair->filename);

    return 0;
}

int unix_socket_accept_getsockname(uint64_t fd, struct sockaddr_un *addr,
                                   socklen_t *addrlen) {
    if (fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -(EBADF);

    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    unix_socket_pair_t *pair = handle->sock;

    addr->sun_family = 1;
    strcpy(addr->sun_path, pair->filename);
    *addrlen = sizeof(addr->sun_family) + strlen(pair->filename);

    return 0;
}

void socket_open(void *parent, const char *name, vfs_node_t node) {}

int socket_stat(void *file, vfs_node_t node) { return 0; }

socket_op_t socket_ops = {
    .accept = socket_accept,
    .listen = socket_listen,
    .getsockname = unix_socket_getsockname,
    .bind = socket_bind,
    .connect = socket_connect,
    .sendto = unix_socket_send_to,
    .recvfrom = unix_socket_recv_from,
    .sendmsg = unix_socket_send_msg,
    .recvmsg = unix_socket_recv_msg,
    .getpeername = unix_socket_getpeername,
    .getsockopt = unix_socket_getsockopt,
    .setsockopt = unix_socket_setsockopt,
};

socket_op_t accept_ops = {
    .getsockname = unix_socket_accept_getsockname,
    .sendto = unix_socket_accept_sendto,
    .recvfrom = unix_socket_accept_recv_from,
    .sendmsg = unix_socket_accept_send_msg,
    .recvmsg = unix_socket_accept_recv_msg,
    .getpeername = unix_socket_accept_getpeername,
    .getsockopt = unix_socket_accept_getsockopt,
    .setsockopt = unix_socket_accept_setsockopt,
};

ssize_t socket_read(fd_t *fd, void *buf, size_t offset, size_t limit) {
    (void)offset;

    void *f = fd->node->handle;

    socket_handle_t *handle = f;
    socket_t *sock = handle->sock;
    unix_socket_pair_t *pair = sock->pair;
    while (true) {
        if (!pair->serverFds && pair->clientBuffPos == 0) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return 0;
        } else if ((handle->fd->flags & O_NONBLOCK) &&
                   pair->clientBuffPos == 0) {
            return -(EWOULDBLOCK);
        } else if (pair->clientBuffPos > 0)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    size_t toCopy = MIN(limit, pair->clientBuffPos);
    memcpy(buf, pair->clientBuff, toCopy);
    memmove(pair->clientBuff, &pair->clientBuff[toCopy],
            pair->clientBuffPos - toCopy);
    pair->clientBuffPos -= toCopy;

    spin_unlock(&pair->lock);

    return toCopy;
}

ssize_t socket_write(fd_t *fd, const void *buf, size_t offset, size_t limit) {
    (void)offset;

    void *f = fd->node->handle;

    socket_handle_t *handle = f;
    socket_t *sock = handle->sock;
    unix_socket_pair_t *pair = sock->pair;

    if (limit > pair->serverBuffSize) {
        limit = pair->serverBuffSize;
    }

    while (true) {
        if (!pair->serverFds) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        } else if ((handle->fd->flags & O_NONBLOCK) &&
                   (pair->serverBuffPos + limit) > pair->serverBuffSize) {
            return -(EWOULDBLOCK);
        }

        if ((pair->serverBuffPos + limit) <= pair->serverBuffSize)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    limit = MIN(limit, pair->serverBuffSize);
    memcpy(&pair->serverBuff[pair->serverBuffPos], buf, limit);
    pair->serverBuffPos += limit;

    spin_unlock(&pair->lock);

    return limit;
}

ssize_t socket_accept_read(fd_t *fd, void *buf, size_t offset, size_t limit) {
    (void)offset;

    void *f = fd->node->handle;

    socket_handle_t *handle = f;
    unix_socket_pair_t *pair = handle->sock;
    while (true) {
        if (!pair->clientFds && pair->serverBuffPos == 0) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return 0;
        } else if ((handle->fd->flags & O_NONBLOCK) &&
                   pair->serverBuffPos == 0) {
            return -(EWOULDBLOCK);
        } else if (pair->serverBuffPos > 0)
            break;

        arch_yield();
    }

    spin_lock(&pair->lock);

    size_t toCopy = MIN(limit, pair->serverBuffPos);
    memcpy(buf, pair->serverBuff, toCopy);
    memmove(pair->serverBuff, &pair->serverBuff[toCopy],
            pair->serverBuffPos - toCopy);
    pair->serverBuffPos -= toCopy;

    spin_unlock(&pair->lock);

    return toCopy;
}

ssize_t socket_accept_write(fd_t *fd, const void *buf, size_t offset,
                            size_t limit) {
    (void)offset;

    void *f = fd->node->handle;

    socket_handle_t *handle = f;
    unix_socket_pair_t *pair = handle->sock;

    if (limit > pair->clientBuffSize) {
        limit = pair->clientBuffSize;
    }

    while (true) {
        if (!pair->clientFds) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }

        if ((pair->clientBuffPos + limit) <= pair->clientBuffSize)
            break;

        if (handle->fd->flags & O_NONBLOCK) {
            return -(EWOULDBLOCK);
        }

        arch_yield();
    }

    spin_lock(&pair->lock);

    limit = MIN(limit, pair->clientBuffSize);
    memcpy(&pair->clientBuff[pair->clientBuffPos], buf, limit);
    pair->clientBuffPos += limit;

    spin_unlock(&pair->lock);

    return limit;
}

static struct vfs_callback socket_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)socket_open,
    .close = (vfs_close_t)socket_socket_close,
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
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)socket_socket_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

static struct vfs_callback accept_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)socket_open,
    .close = (vfs_close_t)socket_accept_close,
    .read = (vfs_read_t)socket_accept_read,
    .write = (vfs_write_t)socket_accept_write,
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
    .poll = (vfs_poll_t)socket_accept_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t sockfs = {
    .name = "sockfs",
    .magic = 0,
    .callback = &socket_callback,
    .flags = FS_FLAGS_HIDDEN,
};

fs_t acceptfs = {
    .name = "acceptfs",
    .magic = 0,
    .callback = &accept_callback,
    .flags = FS_FLAGS_HIDDEN,
};

void socketfs_init() {
    memset(sockets, 0, sizeof(sockets));
    unix_socket_fsid = vfs_regist(&sockfs);
    unix_accept_fsid = vfs_regist(&acceptfs);
    sockfs_root = vfs_node_alloc(NULL, "sock");
    sockfs_root->type = file_dir;
    sockfs_root->mode = 0644;
    memset(&first_unix_socket, 0, sizeof(socket_t));

    regist_socket(1, socket_socket);

    netlink_init();
}
