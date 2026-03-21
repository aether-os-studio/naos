#include <arch/arch.h>
#include <net/net_syscall.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <task/task.h>
#include <net/netlink.h>
#include <libs/hashmap.h>
#include <libs/strerror.h>

extern socket_op_t socket_ops;

int sockfsfd_id = 0;

socket_t first_unix_socket;
static socket_t *unix_socket_list_tail = &first_unix_socket;
spinlock_t unix_socket_list_lock;
static mutex_t unix_socket_bind_lock;

int unix_socket_fsid = 0;

static hashmap_t unix_socket_bind_map = HASHMAP_INIT;

typedef struct unix_socket_bind_bucket {
    uint64_t hash;
    socket_t *head;
} unix_socket_bind_bucket_t;

static inline bool unix_socket_is_dgram_type(int type) {
    return type == SOCK_DGRAM;
}

static inline bool unix_socket_is_connected_type(int type) {
    return type == SOCK_STREAM || type == SOCK_SEQPACKET;
}

static inline bool unix_socket_type_supported(int type) {
    return unix_socket_is_connected_type(type) ||
           unix_socket_is_dgram_type(type);
}

static inline int32_t unix_socket_cred_pid_for_task(task_t *task) {
    if (!task)
        return -1;

    uint64_t pid = task_effective_tgid(task);
    if (pid > INT32_MAX)
        return -1;

    return (int32_t)pid;
}

static inline void unix_socket_fill_cred_from_task(struct ucred *cred,
                                                   task_t *task) {
    if (!cred) {
        return;
    }

    cred->pid = unix_socket_cred_pid_for_task(task);
    cred->uid = task ? task->uid : 0;
    cred->gid = task ? task->gid : 0;
}

static inline void unix_socket_snapshot_peer_cred(socket_t *sock,
                                                  const struct ucred *cred) {
    if (!sock || !cred) {
        return;
    }

    sock->peer_cred = *cred;
    sock->has_peer_cred = true;
}

static inline bool unix_socket_get_peer_cred(const socket_t *sock,
                                             struct ucred *cred) {
    if (!sock || !cred) {
        return false;
    }

    if (sock->has_peer_cred) {
        *cred = sock->peer_cred;
        return true;
    }

    if (!sock->peer) {
        return false;
    }

    *cred = sock->peer->cred;
    return true;
}

static uint64_t unix_socket_name_hash(const char *name) {
    uint64_t hash = 1469598103934665603ULL;
    if (!name)
        return hash;

    while (*name) {
        hash ^= (uint8_t)*name++;
        hash *= 1099511628211ULL;
    }

    return hash;
}

static void unix_socket_unlink_bound_path(const char *path) {
    if (!path || !path[0])
        return;

    vfs_node_t *node = vfs_open(path, O_NOFOLLOW);
    if (!node)
        return;

    vfs_delete(node);
}

static inline unix_socket_bind_bucket_t *
unix_socket_bind_bucket_lookup_locked(uint64_t hash) {
    return (unix_socket_bind_bucket_t *)hashmap_get(&unix_socket_bind_map,
                                                    hash);
}

static socket_t *unix_socket_lookup_bound_locked(const char *name, size_t len,
                                                 socket_t *skip,
                                                 bool take_node_ref) {
    if (!name || !len)
        return NULL;

    uint64_t hash = unix_socket_name_hash(name);
    unix_socket_bind_bucket_t *bucket =
        unix_socket_bind_bucket_lookup_locked(hash);
    socket_t *sock = bucket ? bucket->head : NULL;
    while (sock) {
        if (sock != skip && sock->bindHash == hash && sock->bindAddr &&
            sock->bindAddrLen == len &&
            memcmp(sock->bindAddr, name, len) == 0) {
            if (take_node_ref && sock->node)
                vfs_node_ref_get(sock->node);
            return sock;
        }
        sock = sock->bind_next;
    }

    return NULL;
}

static socket_t *unix_socket_lookup_bound(const char *name, size_t len,
                                          socket_t *skip, bool take_node_ref) {
    socket_t *sock = NULL;

    mutex_lock(&unix_socket_bind_lock);
    sock = unix_socket_lookup_bound_locked(name, len, skip, take_node_ref);
    mutex_unlock(&unix_socket_bind_lock);

    return sock;
}

static inline void unix_socket_release_lookup_ref(socket_t *sock) {
    if (sock && sock->node)
        vfs_node_ref_put(sock->node, NULL);
}

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

static inline socket_t *socket_from_node(vfs_node_t *node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    return handle ? handle->sock : NULL;
}

static inline void socket_pending_mark(socket_t *sock, uint32_t events) {
    if (!sock || !events)
        return;
    __atomic_fetch_or(&sock->pending_events, events, __ATOMIC_RELEASE);
}

static inline uint32_t socket_pending_take(socket_t *sock, uint32_t events) {
    if (!sock || !events)
        return 0;

    uint32_t old_mask = 0;
    uint32_t new_mask = 0;
    do {
        old_mask = __atomic_load_n(&sock->pending_events, __ATOMIC_ACQUIRE);
        if (!(old_mask & events))
            return 0;
        new_mask = old_mask & ~events;
    } while (!__atomic_compare_exchange_n(&sock->pending_events, &old_mask,
                                          new_mask, false, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE));

    return old_mask & events;
}

static inline void socket_notify_node(vfs_node_t *node, uint32_t events) {
    if (!node || !events)
        return;
    vfs_poll_notify(node, events);
}

static inline void socket_notify_sock(socket_t *sock, uint32_t events) {
    if (!sock)
        return;
    socket_pending_mark(sock, events);
    socket_notify_node(sock->node, events);
}

static inline size_t unix_socket_recv_used_locked(const socket_t *sock) {
    return sock ? sock->recv_pos : 0;
}

static inline size_t unix_socket_recv_space_locked(const socket_t *sock) {
    if (!sock || sock->recv_pos >= sock->recv_size)
        return 0;
    return sock->recv_size - sock->recv_pos;
}

static size_t unix_socket_recv_write_locked(socket_t *sock, const uint8_t *data,
                                            size_t len) {
    if (!sock || !data || !len)
        return 0;

    size_t to_copy = MIN(len, unix_socket_recv_space_locked(sock));
    if (!to_copy)
        return 0;

    size_t tail = (sock->recv_head + sock->recv_pos) % sock->recv_size;
    size_t first = MIN(to_copy, sock->recv_size - tail);
    memcpy(sock->recv_buff + tail, data, first);
    if (to_copy > first) {
        memcpy(sock->recv_buff, data + first, to_copy - first);
    }

    sock->recv_pos += to_copy;
    return to_copy;
}

static size_t unix_socket_recv_copy_out_locked(const socket_t *sock,
                                               size_t start, uint8_t *out,
                                               size_t len) {
    if (!sock || !out || !len || !sock->recv_size)
        return 0;

    size_t head = (sock->recv_head + start) % sock->recv_size;
    size_t first = MIN(len, sock->recv_size - head);
    memcpy(out, sock->recv_buff + head, first);
    if (len > first) {
        memcpy(out + first, sock->recv_buff, len - first);
    }

    return len;
}

static size_t unix_socket_recv_read_locked(socket_t *sock, uint8_t *out,
                                           size_t len, bool peek) {
    if (!sock || !out || !len)
        return 0;

    size_t to_copy = MIN(len, unix_socket_recv_used_locked(sock));
    if (!to_copy)
        return 0;

    unix_socket_recv_copy_out_locked(sock, 0, out, to_copy);

    if (!peek) {
        sock->recv_head = (sock->recv_head + to_copy) % sock->recv_size;
        sock->recv_pos -= to_copy;
        if (!sock->recv_pos)
            sock->recv_head = 0;
    }

    return to_copy;
}

static size_t unix_socket_recv_readv_locked(socket_t *sock,
                                            const struct iovec *iov,
                                            size_t iovlen, size_t len_total,
                                            bool peek) {
    if (!sock || !iov || !iovlen || !len_total)
        return 0;

    size_t remaining = MIN(len_total, unix_socket_recv_used_locked(sock));
    size_t consumed = 0;

    for (size_t i = 0; i < iovlen && remaining > 0; i++) {
        if (!iov[i].iov_base || !iov[i].len)
            continue;

        size_t copy_len = MIN(iov[i].len, remaining);
        unix_socket_recv_copy_out_locked(sock, consumed, iov[i].iov_base,
                                         copy_len);
        consumed += copy_len;
        remaining -= copy_len;
    }

    if (!peek && consumed > 0) {
        sock->recv_head = (sock->recv_head + consumed) % sock->recv_size;
        sock->recv_pos -= consumed;
        if (!sock->recv_pos)
            sock->recv_head = 0;
    }

    return consumed;
}

static void unix_socket_ancillary_free(unix_socket_ancillary_t *ancillary) {
    if (!ancillary)
        return;

    for (uint32_t i = 0; i < ancillary->file_count; i++) {
        if (ancillary->files[i])
            fd_release(ancillary->files[i]);
    }

    free(ancillary);
}

static void
unix_socket_ancillary_free_list(unix_socket_ancillary_t *ancillary_list) {
    while (ancillary_list) {
        unix_socket_ancillary_t *next = ancillary_list->next;
        unix_socket_ancillary_free(ancillary_list);
        ancillary_list = next;
    }
}

static void unix_socket_ancillary_enqueue_locked(socket_t *sock,
                                                 unix_socket_ancillary_t *anc) {
    if (!sock || !anc)
        return;

    anc->next = NULL;
    if (sock->ancillary_tail) {
        sock->ancillary_tail->next = anc;
    } else {
        sock->ancillary_head = anc;
    }
    sock->ancillary_tail = anc;
}

static void unix_socket_ancillary_drop_before_locked(socket_t *sock,
                                                     uint64_t seq_limit) {
    if (!sock)
        return;

    while (sock->ancillary_head && sock->ancillary_head->seq < seq_limit) {
        unix_socket_ancillary_t *stale = sock->ancillary_head;
        sock->ancillary_head = stale->next;
        if (!sock->ancillary_head)
            sock->ancillary_tail = NULL;
        stale->next = NULL;
        unix_socket_ancillary_free(stale);
    }
}

static unix_socket_ancillary_t *
unix_socket_ancillary_clone_one(const unix_socket_ancillary_t *src) {
    if (!src)
        return NULL;

    unix_socket_ancillary_t *clone = calloc(1, sizeof(*clone));
    if (!clone)
        return NULL;

    clone->seq = src->seq;
    clone->file_count = src->file_count;
    clone->cred = src->cred;
    clone->has_cred = src->has_cred;

    for (uint32_t i = 0; i < src->file_count; i++) {
        clone->files[i] = vfs_dup(src->files[i]);
        if (!clone->files[i]) {
            unix_socket_ancillary_free(clone);
            return NULL;
        }
    }

    return clone;
}

static size_t unix_socket_iov_total_len(const struct iovec *iov,
                                        size_t iovlen) {
    size_t total = 0;

    if (!iov)
        return 0;

    for (size_t i = 0; i < iovlen; i++)
        total += iov[i].len;

    return total;
}

static size_t unix_socket_stream_read_limit_locked(const socket_t *sock,
                                                   size_t requested) {
    size_t limit = MIN(requested, unix_socket_recv_used_locked(sock));
    if (!sock || !limit)
        return limit;

    unix_socket_ancillary_t *ancillary = sock->ancillary_head;
    while (ancillary && ancillary->seq < sock->recv_seq)
        ancillary = ancillary->next;

    if (ancillary && ancillary->seq < sock->recv_seq + limit)
        limit = (size_t)(ancillary->seq - sock->recv_seq + 1);

    return limit;
}

static int unix_socket_prepare_ancillary(const struct msghdr *msg,
                                         unix_socket_ancillary_t **out_anc) {
    if (!out_anc)
        return -EINVAL;

    *out_anc = NULL;
    if (!msg || !msg->msg_control || msg->msg_controllen == 0)
        return 0;

    unix_socket_ancillary_t *anc = calloc(1, sizeof(*anc));
    if (!anc)
        return -ENOMEM;

    bool have_rights = false;
    bool have_cred = false;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET)
            continue;

        if (cmsg->cmsg_type == SCM_RIGHTS) {
            if (have_rights || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
                unix_socket_ancillary_free(anc);
                return -EINVAL;
            }

            size_t rights_len = cmsg->cmsg_len - CMSG_LEN(0);
            if ((rights_len % sizeof(int)) != 0) {
                unix_socket_ancillary_free(anc);
                return -EINVAL;
            }

            uint32_t file_count = rights_len / sizeof(int);
            if (file_count == 0 || file_count > MAX_PENDING_FILES_COUNT) {
                unix_socket_ancillary_free(anc);
                return -ETOOMANYREFS;
            }

            int *fds = (int *)CMSG_DATA(cmsg);
            for (uint32_t i = 0; i < file_count; i++) {
                int send_fd = fds[i];
                if (send_fd < 0 || send_fd >= MAX_FD_NUM ||
                    !current_task->fd_info->fds[send_fd]) {
                    unix_socket_ancillary_free(anc);
                    return -EBADF;
                }

                anc->files[anc->file_count] =
                    vfs_dup(current_task->fd_info->fds[send_fd]);
                if (!anc->files[anc->file_count]) {
                    unix_socket_ancillary_free(anc);
                    return -ENOMEM;
                }
                anc->file_count++;
            }

            have_rights = true;
        } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (have_cred || cmsg->cmsg_len < CMSG_LEN(sizeof(struct ucred))) {
                unix_socket_ancillary_free(anc);
                return -EINVAL;
            }

            struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
            if (current_task->euid != 0 &&
                (cred->pid != unix_socket_cred_pid_for_task(current_task) ||
                 cred->uid != current_task->uid ||
                 cred->gid != current_task->gid)) {
                unix_socket_ancillary_free(anc);
                return -EPERM;
            }

            anc->cred = *cred;
            anc->has_cred = true;
            have_cred = true;
        }
    }

    if (!anc->file_count && !anc->has_cred) {
        free(anc);
        return 0;
    }

    *out_anc = anc;
    return 0;
}

static int unix_socket_collect_ancillary_locked(socket_t *sock,
                                                uint64_t end_seq, bool peek,
                                                unix_socket_ancillary_t **out) {
    if (!out)
        return -EINVAL;

    *out = NULL;
    if (!sock)
        return 0;

    unix_socket_ancillary_t *list = NULL;
    unix_socket_ancillary_t *tail = NULL;

    if (peek) {
        for (unix_socket_ancillary_t *curr = sock->ancillary_head;
             curr && curr->seq < end_seq; curr = curr->next) {
            unix_socket_ancillary_t *clone =
                unix_socket_ancillary_clone_one(curr);
            if (!clone) {
                unix_socket_ancillary_free_list(list);
                return -ENOMEM;
            }

            if (tail) {
                tail->next = clone;
            } else {
                list = clone;
            }
            tail = clone;
        }
    } else {
        while (sock->ancillary_head && sock->ancillary_head->seq < end_seq) {
            unix_socket_ancillary_t *curr = sock->ancillary_head;
            sock->ancillary_head = curr->next;
            if (!sock->ancillary_head)
                sock->ancillary_tail = NULL;
            curr->next = NULL;

            if (tail) {
                tail->next = curr;
            } else {
                list = curr;
            }
            tail = curr;
        }
    }

    *out = list;
    return 0;
}

static int socket_wait_node(vfs_node_t *node, uint32_t events,
                            const char *reason) {
    if (!node || !current_task)
        return -EINVAL;

    socket_t *wait_sock = socket_from_node(node);
    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    if (socket_pending_take(wait_sock, want))
        return EOK;
    int polled = vfs_poll(node, want);
    if (polled < 0)
        return polled;
    if (polled & (int)want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(node, &wait) < 0)
        return -EINVAL;

    if (socket_pending_take(wait_sock, want)) {
        vfs_poll_wait_disarm(&wait);
        return EOK;
    }

    polled = vfs_poll(node, want);
    if (polled < 0) {
        vfs_poll_wait_disarm(&wait);
        return polled;
    }
    if (polled & (int)want) {
        vfs_poll_wait_disarm(&wait);
        return EOK;
    }

    int ret = vfs_poll_wait_sleep(node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
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
    if (!sock)
        return NULL;
    memset(sock, 0, sizeof(socket_t));
    mutex_init(&sock->lock);

    sock->recv_size = BUFFER_SIZE;
    sock->recv_buff = alloc_frames_bytes(BUFFER_SIZE);
    if (!sock->recv_buff) {
        free(sock);
        return NULL;
    }
    sock->recv_head = 0;
    sock->recv_pos = 0;
    sock->recv_seq = 0;
    sock->node = NULL;
    sock->ancillary_head = NULL;
    sock->ancillary_tail = NULL;

    // 设置凭据
    unix_socket_fill_cred_from_task(&sock->cred, current_task);

    // 加入链表
    spin_lock(&unix_socket_list_lock);
    unix_socket_list_tail->next = sock;
    unix_socket_list_tail = sock;
    spin_unlock(&unix_socket_list_lock);

    return sock;
}

void unix_socket_free(socket_t *sock) {
    if (!sock)
        return;

    if (sock->bindAddr) {
        mutex_lock(&unix_socket_bind_lock);
        unix_socket_bind_bucket_t *bucket =
            unix_socket_bind_bucket_lookup_locked(sock->bindHash);
        socket_t *bind_head = bucket ? bucket->head : NULL;
        socket_t *prev = NULL;
        socket_t *curr = bind_head;
        while (curr && curr != sock) {
            prev = curr;
            curr = curr->bind_next;
        }
        if (curr == sock) {
            if (prev) {
                prev->bind_next = curr->bind_next;
            } else {
                if (bucket)
                    bucket->head = curr->bind_next;
                if (!bucket || !bucket->head) {
                    hashmap_remove(&unix_socket_bind_map, sock->bindHash);
                    free(bucket);
                }
            }
            curr->bind_next = NULL;
        }
        mutex_unlock(&unix_socket_bind_lock);
    }

    // 从链表移除
    spin_lock(&unix_socket_list_lock);
    socket_t *browse = &first_unix_socket;
    while (browse && browse->next != sock)
        browse = browse->next;
    if (browse) {
        browse->next = sock->next;
        if (unix_socket_list_tail == sock)
            unix_socket_list_tail = browse;
    }
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

    unix_socket_ancillary_free_list(sock->ancillary_head);

    free(sock);
}

// 发送数据到对端的 recv_buff
static size_t unix_socket_send_to_peer(socket_t *self, socket_t *peer,
                                       const uint8_t *data, size_t len,
                                       int flags, fd_t *fd_handle,
                                       unix_socket_ancillary_t **ancillary) {
    socket_t *active_peer = peer;
    if (self && !unix_socket_is_dgram_type(self->type))
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
        if (self && !unix_socket_is_dgram_type(self->type))
            active_peer = self->peer;
        if (!active_peer) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }

        mutex_lock(&active_peer->lock);
        if (active_peer->closed || active_peer->shut_rd) {
            mutex_unlock(&active_peer->lock);
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }
        size_t available = unix_socket_recv_space_locked(active_peer);
        if (available > 0) {
            if (ancillary && *ancillary) {
                (*ancillary)->seq =
                    active_peer->recv_seq + active_peer->recv_pos;
                unix_socket_ancillary_enqueue_locked(active_peer, *ancillary);
                *ancillary = NULL;
            }
            size_t to_copy =
                unix_socket_recv_write_locked(active_peer, data, len);
            mutex_unlock(&active_peer->lock);
            socket_notify_sock(active_peer, EPOLLIN);
            return to_copy;
        }
        mutex_unlock(&active_peer->lock);

        if ((fd_handle && (fd_get_flags(fd_handle) & O_NONBLOCK)) ||
            (flags & MSG_DONTWAIT)) {
            return -(EWOULDBLOCK);
        }

        vfs_node_t *wait_node = NULL;
        if (self && !unix_socket_is_dgram_type(self->type) && self->node)
            wait_node = self->node;
        if (!wait_node && active_peer->node)
            wait_node = active_peer->node;
        if (!wait_node)
            return -EINVAL;
        int reason = socket_wait_node(wait_node, EPOLLOUT, "socket_send");
        if (reason != EOK)
            return -EINTR;
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
        mutex_lock(&self->lock);

        if (self->recv_pos > 0) {
            size_t limit = len;
            if (!unix_socket_is_dgram_type(self->type))
                limit = unix_socket_stream_read_limit_locked(self, len);
            size_t to_copy =
                unix_socket_recv_read_locked(self, buf, limit, peek);
            if (!peek) {
                self->recv_seq += to_copy;
                unix_socket_ancillary_drop_before_locked(self, self->recv_seq);
            }
            mutex_unlock(&self->lock);
            if (!peek) {
                socket_notify_sock(self, EPOLLOUT);
                if (self->peer)
                    socket_notify_sock(self->peer, EPOLLOUT);
            }
            return to_copy;
        }

        socket_t *active_peer = peer;
        if (!unix_socket_is_dgram_type(self->type))
            active_peer = self->peer;
        bool eof =
            (!active_peer || active_peer->closed || active_peer->shut_wr);
        mutex_unlock(&self->lock);

        // 对端关闭且没有数据 = EOF
        if (eof) {
            return 0;
        }

        if ((fd_handle && (fd_get_flags(fd_handle) & O_NONBLOCK)) ||
            (flags & MSG_DONTWAIT)) {
            return -(EWOULDBLOCK);
        }

        if (!self->node)
            return -EINVAL;
        int reason = socket_wait_node(self->node, EPOLLIN, "socket_recv");
        if (reason != EOK)
            return -EINTR;
    }
}

static size_t unix_socket_recvmsg_from_self(socket_t *self, socket_t *peer,
                                            struct msghdr *msg, int flags,
                                            fd_t *fd_handle,
                                            uint64_t *start_seq_out) {
    bool peek = !!(flags & MSG_PEEK);

    if (!self || !msg)
        return -EINVAL;
    if (self->shut_rd)
        return 0;

    size_t len_total = unix_socket_iov_total_len(msg->msg_iov, msg->msg_iovlen);

    if (!len_total)
        return 0;

    while (true) {
        mutex_lock(&self->lock);

        if (self->recv_pos > 0) {
            uint64_t start_seq = self->recv_seq;
            size_t limit = len_total;
            if (!unix_socket_is_dgram_type(self->type))
                limit = unix_socket_stream_read_limit_locked(self, len_total);
            size_t copied = unix_socket_recv_readv_locked(
                self, msg->msg_iov, msg->msg_iovlen, limit, peek);
            if (!peek)
                self->recv_seq += copied;
            mutex_unlock(&self->lock);
            if (start_seq_out)
                *start_seq_out = start_seq;
            if (!peek) {
                socket_notify_sock(self, EPOLLOUT);
                if (self->peer)
                    socket_notify_sock(self->peer, EPOLLOUT);
            }
            return copied;
        }

        socket_t *active_peer = peer;
        if (!unix_socket_is_dgram_type(self->type))
            active_peer = self->peer;
        bool eof =
            (!active_peer || active_peer->closed || active_peer->shut_wr);
        mutex_unlock(&self->lock);

        if (eof)
            return 0;

        if ((fd_handle && (fd_get_flags(fd_handle) & O_NONBLOCK)) ||
            (flags & MSG_DONTWAIT)) {
            return -(EWOULDBLOCK);
        }

        if (!self->node)
            return -EINVAL;
        int reason = socket_wait_node(self->node, EPOLLIN, "socket_recvmsg");
        if (reason != EOK)
            return -EINTR;
    }
}

static void unix_socket_drop_pending_file(fd_t *pending_file) {
    if (!pending_file)
        return;
    fd_release(pending_file);
}

static size_t unix_socket_install_pending_files(fd_t **pending_files,
                                                size_t pending_count,
                                                int *fds_out, int *msg_flags,
                                                int recv_flags) {
    size_t installed = 0;
    with_fd_info_lock(current_task->fd_info, {
        for (size_t i = 0; i < pending_count; i++) {
            int new_fd = -1;
            for (int fd_idx = 0; fd_idx < MAX_FD_NUM; fd_idx++) {
                if (current_task->fd_info->fds[fd_idx] == NULL) {
                    new_fd = fd_idx;
                    break;
                }
            }

            if (new_fd < 0)
                break;

            fd_t *new_entry = vfs_dup(pending_files[i]);
            if (!new_entry)
                break;
            new_entry->close_on_exec = !!(recv_flags & MSG_CMSG_CLOEXEC);
            current_task->fd_info->fds[new_fd] = new_entry;
            fds_out[installed++] = new_fd;
        }
    });

    for (size_t i = 0; i < installed; i++) {
        fd_release(pending_files[i]);
        pending_files[i] = NULL;
        procfs_on_open_file(current_task, fds_out[i]);
    }

    if (installed < pending_count) {
        if (msg_flags)
            *msg_flags |= MSG_CTRUNC;
        for (size_t i = installed; i < pending_count; i++) {
            unix_socket_drop_pending_file(pending_files[i]);
            pending_files[i] = NULL;
        }
    }

    return installed;
}

vfs_node_t *unix_socket_create_node(socket_t *sock) {
    vfs_node_t *socknode = vfs_node_alloc(NULL, NULL);
    if (!socknode)
        return NULL;
    socknode->refcount++;
    socknode->type = file_socket;
    socknode->mode = 0700;
    socknode->fsid = unix_socket_fsid;

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    if (!handle) {
        vfs_free(socknode);
        return NULL;
    }
    memset(handle, 0, sizeof(socket_handle_t));
    handle->op = &socket_ops;
    handle->sock = sock;

    socknode->handle = handle;
    sock->node = socknode;
    return socknode;
}

int socket_socket(int domain, int type, int protocol) {
    int sock_type = type & 0xF;
    if (!unix_socket_type_supported(sock_type)) {
        return -ESOCKTNOSUPPORT;
    }

    socket_t *sock = unix_socket_alloc();
    if (!sock)
        return -ENOMEM;

    sock->domain = domain;
    sock->type = sock_type;
    sock->protocol = protocol;

    vfs_node_t *socknode = unix_socket_create_node(sock);
    if (!socknode) {
        unix_socket_free(sock);
        return -ENOMEM;
    }
    socket_handle_t *handle = socknode->handle;

    int ret = -EMFILE;
    uint64_t i = 0;
    uint64_t flags = O_RDWR;
    with_fd_info_lock(current_task->fd_info, {
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL)
                break;
        }

        if (i == MAX_FD_NUM)
            break;

        if (type & O_NONBLOCK)
            flags |= O_NONBLOCK;
        fd_t *new_fd = fd_create(socknode, flags, !!(type & O_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }

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
    size_t safeLen = strlen(safe);

    if (!is_abstract) {
        vfs_node_t *existing = vfs_open(safe, 0);
        if (existing) {
            vfs_close(existing);
            free(safe);
            return -EADDRINUSE;
        }
        int mkret = vfs_mknod(safe, S_IFSOCK | 0666, 0);
        if (mkret < 0) {
            free(safe);
            return mkret;
        }
    }

    uint64_t bind_hash = unix_socket_name_hash(safe);
    mutex_lock(&unix_socket_bind_lock);
    if (unix_socket_lookup_bound_locked(safe, safeLen, sock, false)) {
        mutex_unlock(&unix_socket_bind_lock);
        free(safe);
        return -EADDRINUSE;
    }

    unix_socket_bind_bucket_t *bucket =
        unix_socket_bind_bucket_lookup_locked(bind_hash);
    if (!bucket) {
        bucket = calloc(1, sizeof(*bucket));
        if (!bucket) {
            mutex_unlock(&unix_socket_bind_lock);
            if (!is_abstract)
                unix_socket_unlink_bound_path(safe);
            free(safe);
            return -ENOMEM;
        }
        bucket->hash = bind_hash;
        if (hashmap_put(&unix_socket_bind_map, bind_hash, bucket) != 0) {
            free(bucket);
            mutex_unlock(&unix_socket_bind_lock);
            if (!is_abstract)
                unix_socket_unlink_bound_path(safe);
            free(safe);
            return -ENOMEM;
        }
    }

    sock->bindAddr = safe;
    sock->bindAddrLen = safeLen;
    sock->bindHash = bind_hash;
    sock->bind_next = bucket->head;
    bucket->head = sock;
    mutex_unlock(&unix_socket_bind_lock);

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
    unix_socket_fill_cred_from_task(&sock->cred, current_task);
    if (sock->backlog) {
        free(sock->backlog);
        sock->backlog = NULL;
    }
    sock->connMax = backlog;
    sock->backlog = calloc(sock->connMax, sizeof(socket_t *));
    sock->connCurr = 0;
    sock->connHead = 0;
    if (sock->connMax > 0 && !sock->backlog) {
        sock->connMax = 0;
        mutex_unlock(&sock->lock);
        return -ENOMEM;
    }
    mutex_unlock(&sock->lock);
    return 0;
}

int socket_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen,
                  uint64_t flags) {
    if (fd >= MAX_FD_NUM) {
        return -EBADF;
    }

    fd_t *listener_fd = NULL;
    with_fd_info_lock(current_task->fd_info, {
        if (current_task->fd_info->fds[fd]) {
            listener_fd = vfs_dup(current_task->fd_info->fds[fd]);
        }
    });
    if (!listener_fd) {
        return -EBADF;
    }

    socket_handle_t *handle = listener_fd->node->handle;
    socket_t *listen_sock = handle->sock;

    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
        fd_release(listener_fd);
        return -EINVAL;
    }

    if (addr && !addrlen) {
        fd_release(listener_fd);
        return -EFAULT;
    }

    bool listener_nonblock = !!(fd_get_flags(listener_fd) & O_NONBLOCK);

    if (!listen_sock->connMax || !listen_sock->backlog) {
        fd_release(listener_fd);
        return -EINVAL;
    }

    // 等待连接并从 backlog 取一个
    socket_t *server_sock = NULL;
    while (true) {
        mutex_lock(&listen_sock->lock);
        if (listen_sock->connCurr > 0) {
            int head = listen_sock->connHead;
            server_sock = listen_sock->backlog[head];
            listen_sock->backlog[head] = NULL;
            listen_sock->connHead =
                (listen_sock->connHead + 1) % listen_sock->connMax;
            listen_sock->connCurr--;
            if (listen_sock->connCurr == 0)
                listen_sock->connHead = 0;
            mutex_unlock(&listen_sock->lock);
            socket_notify_sock(listen_sock, EPOLLOUT);
            break;
        }
        mutex_unlock(&listen_sock->lock);
        if (fd_get_flags(listener_fd) & O_NONBLOCK) {
            fd_release(listener_fd);
            return -(EWOULDBLOCK);
        }
        int reason =
            socket_wait_node(listener_fd->node, EPOLLIN, "socket_accept");
        if (reason != EOK) {
            fd_release(listener_fd);
            return -EINTR;
        }
    }

    if (!server_sock) {
        fd_release(listener_fd);
        return -ECONNABORTED;
    }

    // 创建节点
    vfs_node_t *acceptFd = unix_socket_create_node(server_sock);
    if (!acceptFd) {
        fd_release(listener_fd);
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
            socket_notify_sock(server_sock->peer,
                               EPOLLERR | EPOLLHUP | EPOLLRDHUP);
        }
        unix_socket_free(server_sock);
        return -ENOMEM;
    }

    int ret = -EMFILE;
    uint64_t i = 0;
    fd_t *accepted_fd = NULL;
    with_fd_info_lock(current_task->fd_info, {
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL)
                break;
        }

        if (i == MAX_FD_NUM)
            break;

        uint64_t accept_flags = O_RDWR;
        if ((flags & O_NONBLOCK) || listener_nonblock)
            accept_flags |= O_NONBLOCK;
        fd_t *new_fd = fd_create(acceptFd, accept_flags, !!(flags & O_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            break;
        }
        current_task->fd_info->fds[i] = new_fd;
        accepted_fd = new_fd;
        procfs_on_open_file(current_task, i);
        ret = (int)i;
    });

    fd_release(listener_fd);

    if (ret < 0) {
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
            socket_notify_sock(server_sock->peer,
                               EPOLLERR | EPOLLHUP | EPOLLRDHUP);
        }
        unix_socket_free(server_sock);
        vfs_free(acceptFd);
        return ret;
    }

    socket_handle_t *accept_handle = acceptFd->handle;
    accept_handle->fd = accepted_fd;

    if (server_sock->peer) {
        socket_notify_sock(server_sock->peer, EPOLLOUT);
    }

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

    if (unix_socket_is_connected_type(sock->type) && !sock->peer &&
        !sock->established && sock->connMax == 0)
        return -ENOTCONN;

    if (how == SHUT_RD || how == SHUT_RDWR)
        sock->shut_rd = true;
    if (how == SHUT_WR || how == SHUT_RDWR)
        sock->shut_wr = true;

    socket_notify_sock(sock, EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP);
    if (sock->peer)
        socket_notify_sock(sock->peer,
                           EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP);

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
    socket_t *listen_sock = unix_socket_lookup_bound(safe, safeLen, sock, true);

    if (!listen_sock) {
        int ret = -ENOENT;
        if (!is_abstract) {
            vfs_node_t *path_node = vfs_open(safe, 0);
            if (path_node) {
                ret = -ECONNREFUSED;
                vfs_close(path_node);
            }
        }
        free(safe);
        return ret;
    }
    free(safe);

    while (true) {
        mutex_lock(&listen_sock->lock);
        if (listen_sock->closed || !listen_sock->connMax ||
            !listen_sock->backlog) {
            mutex_unlock(&listen_sock->lock);
            unix_socket_release_lookup_ref(listen_sock);
            return -ECONNREFUSED;
        }
        bool queue_available = listen_sock->connCurr < listen_sock->connMax;
        mutex_unlock(&listen_sock->lock);

        if (queue_available)
            break;

        if ((fd_get_flags(current_task->fd_info->fds[fd]) & O_NONBLOCK)) {
            unix_socket_release_lookup_ref(listen_sock);
            return -EAGAIN;
        }
        int reason =
            socket_wait_node(listen_sock->node, EPOLLOUT, "socket_connect");
        if (reason != EOK) {
            unix_socket_release_lookup_ref(listen_sock);
            return -EINTR;
        }
    }

    socket_t *server_sock = unix_socket_alloc();
    if (!server_sock) {
        unix_socket_release_lookup_ref(listen_sock);
        return -ENOMEM;
    }

    server_sock->domain = listen_sock->domain;
    server_sock->type = listen_sock->type;
    server_sock->protocol = listen_sock->protocol;
    server_sock->cred = listen_sock->cred;
    server_sock->passcred = listen_sock->passcred;
    unix_socket_fill_cred_from_task(&sock->cred, current_task);
    unix_socket_snapshot_peer_cred(sock, &server_sock->cred);
    unix_socket_snapshot_peer_cred(server_sock, &sock->cred);
    if (listen_sock->bindAddr) {
        server_sock->filename = strdup(listen_sock->bindAddr);
        if (!server_sock->filename) {
            unix_socket_release_lookup_ref(listen_sock);
            unix_socket_free(server_sock);
            return -ENOMEM;
        }
    }

    server_sock->peer = sock;
    sock->peer = server_sock;
    server_sock->established = true;
    sock->established = true;

    mutex_lock(&listen_sock->lock);
    if (listen_sock->closed || !listen_sock->connMax || !listen_sock->backlog ||
        listen_sock->connCurr >= listen_sock->connMax) {
        mutex_unlock(&listen_sock->lock);
        sock->peer = NULL;
        sock->established = false;
        server_sock->peer = NULL;
        unix_socket_release_lookup_ref(listen_sock);
        unix_socket_free(server_sock);
        return -ECONNREFUSED;
    }
    int tail =
        (listen_sock->connHead + listen_sock->connCurr) % listen_sock->connMax;
    listen_sock->backlog[tail] = server_sock;
    listen_sock->connCurr++;
    mutex_unlock(&listen_sock->lock);
    socket_notify_sock(listen_sock, EPOLLIN);
    socket_notify_sock(sock, EPOLLOUT);
    unix_socket_release_lookup_ref(listen_sock);

    return 0;
}

size_t unix_socket_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags,
                          struct sockaddr_un *addr, uint32_t len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;
    bool peer_needs_unref = false;

    if (!peer) {
        if (!unix_socket_is_dgram_type(sock->type) && sock->established) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return (size_t)-EPIPE;
        }

        if (addr && len) {
            char *safe = unix_socket_addr_safe(addr, len);
            if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
                return (uint64_t)safe;
            size_t safeLen = strlen(safe);
            socket_t *peer_sock =
                unix_socket_lookup_bound(safe, safeLen, sock, true);
            free(safe);

            if (peer_sock) {
                peer = peer_sock;
                peer_needs_unref = true;
                goto done;
            }
        }
        if (unix_socket_is_dgram_type(sock->type))
            return (size_t)-EDESTADDRREQ;
        return (size_t)-ENOTCONN;
    }

done:
    size_t ret =
        unix_socket_send_to_peer(sock, peer, in, limit, flags, caller_fd, NULL);
    if (peer_needs_unref)
        unix_socket_release_lookup_ref(peer);
    return ret;
}

size_t unix_socket_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags,
                            struct sockaddr_un *addr, uint32_t *len) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;

    if (!unix_socket_is_dgram_type(sock->type) && !sock->peer &&
        !sock->established && sock->recv_pos == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, out, limit, flags,
                                      caller_fd);
}

size_t unix_socket_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;
    bool peer_needs_unref = false;

    if (!peer) {
        if (!unix_socket_is_dgram_type(sock->type) && sock->established) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return (size_t)-EPIPE;
        }

        if (msg->msg_name && msg->msg_namelen) {
            char *safe = unix_socket_addr_safe(msg->msg_name, msg->msg_namelen);
            if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
                return (uint64_t)safe;
            size_t safeLen = strlen(safe);
            socket_t *peer_sock =
                unix_socket_lookup_bound(safe, safeLen, sock, true);
            free(safe);

            if (peer_sock) {
                peer = peer_sock;
                peer_needs_unref = true;
                goto done;
            }
        }
        if (unix_socket_is_dgram_type(sock->type))
            return (size_t)-EDESTADDRREQ;
        return (size_t)-ENOTCONN;
    }

done:
    size_t total_len = unix_socket_iov_total_len(msg->msg_iov, msg->msg_iovlen);
    unix_socket_ancillary_t *ancillary = NULL;
    int ancillary_ret = unix_socket_prepare_ancillary(msg, &ancillary);
    if (ancillary_ret < 0) {
        if (peer_needs_unref)
            unix_socket_release_lookup_ref(peer);
        return (size_t)ancillary_ret;
    }

    if (sock->passcred || peer->passcred) {
        if (!ancillary) {
            ancillary = calloc(1, sizeof(*ancillary));
            if (!ancillary) {
                if (peer_needs_unref)
                    unix_socket_release_lookup_ref(peer);
                return (size_t)-ENOMEM;
            }
        }
        if (!ancillary->has_cred) {
            ancillary->cred.pid = unix_socket_cred_pid_for_task(current_task);
            ancillary->cred.uid = current_task->uid;
            ancillary->cred.gid = current_task->gid;
            ancillary->has_cred = true;
        }
    }

    if (ancillary && total_len == 0) {
        unix_socket_ancillary_free(ancillary);
        if (peer_needs_unref)
            unix_socket_release_lookup_ref(peer);
        return (size_t)-EINVAL;
    }

    // 发送数据
    size_t cnt = 0;
    bool noblock = !!(flags & MSG_DONTWAIT);
    unix_socket_ancillary_t *ancillary_to_attach = ancillary;

    for (int i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *curr = &((struct iovec *)msg->msg_iov)[i];
        size_t sent = 0;
        while (sent < curr->len) {
            const uint8_t *base = (const uint8_t *)curr->iov_base;
            size_t ret = unix_socket_send_to_peer(
                sock, peer, base + sent, curr->len - sent,
                noblock ? (flags | MSG_DONTWAIT) : flags, caller_fd,
                &ancillary_to_attach);
            if ((int64_t)ret < 0) {
                if (peer_needs_unref)
                    unix_socket_release_lookup_ref(peer);
                if (ancillary_to_attach)
                    unix_socket_ancillary_free(ancillary_to_attach);
                if (cnt > 0) {
                    return cnt;
                }
                return ret;
            }
            if (ret == 0) {
                if (peer_needs_unref)
                    unix_socket_release_lookup_ref(peer);
                if (ancillary_to_attach)
                    unix_socket_ancillary_free(ancillary_to_attach);
                return cnt;
            }
            sent += ret;
            cnt += ret;
        }
    }

    if (peer_needs_unref)
        unix_socket_release_lookup_ref(peer);
    if (ancillary_to_attach)
        unix_socket_ancillary_free(ancillary_to_attach);
    return cnt;
}

size_t unix_socket_recvmsg(uint64_t fd, struct msghdr *msg, int flags) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    if (!unix_socket_is_dgram_type(sock->type) && !sock->peer &&
        !sock->established && sock->recv_pos == 0)
        return (size_t)-ENOTCONN;

    msg->msg_flags = 0;
    uint64_t start_seq = 0;
    size_t cnt = unix_socket_recvmsg_from_self(sock, NULL, msg, flags,
                                               caller_fd, &start_seq);
    if ((int64_t)cnt < 0)
        return cnt;

    uint64_t end_seq = start_seq + cnt;
    unix_socket_ancillary_t *ancillary_list = NULL;
    mutex_lock(&sock->lock);
    int ancillary_ret = unix_socket_collect_ancillary_locked(
        sock, end_seq, !!(flags & MSG_PEEK), &ancillary_list);
    mutex_unlock(&sock->lock);
    if (ancillary_ret < 0)
        return (size_t)ancillary_ret;

    if (ancillary_list && msg->msg_control &&
        msg->msg_controllen >= sizeof(struct cmsghdr)) {
        size_t controllen_used = 0;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

        for (unix_socket_ancillary_t *anc = ancillary_list; anc != NULL;
             anc = anc->next) {
            if (anc->file_count > 0) {
                size_t space_left = msg->msg_controllen - controllen_used;
                if (cmsg &&
                    space_left >= CMSG_SPACE(anc->file_count * sizeof(int))) {
                    int *fds_out = (int *)CMSG_DATA(cmsg);
                    size_t installed = unix_socket_install_pending_files(
                        anc->files, anc->file_count, fds_out, &msg->msg_flags,
                        flags);
                    anc->file_count = 0;

                    if (installed > 0) {
                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_RIGHTS;
                        cmsg->cmsg_len = CMSG_LEN(installed * sizeof(int));
                        controllen_used += CMSG_SPACE(installed * sizeof(int));
                        cmsg = CMSG_NXTHDR(msg, cmsg);
                    }
                } else {
                    msg->msg_flags |= MSG_CTRUNC;
                }
            }

            if (anc->has_cred) {
                size_t space_left = msg->msg_controllen - controllen_used;
                if (cmsg && space_left >= CMSG_SPACE(sizeof(struct ucred))) {
                    cmsg->cmsg_level = SOL_SOCKET;
                    cmsg->cmsg_type = SCM_CREDENTIALS;
                    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                    memcpy(CMSG_DATA(cmsg), &anc->cred, sizeof(struct ucred));
                    controllen_used += CMSG_SPACE(sizeof(struct ucred));
                    cmsg = CMSG_NXTHDR(msg, cmsg);
                } else {
                    msg->msg_flags |= MSG_CTRUNC;
                }
            }
        }

        msg->msg_controllen = controllen_used;
    } else {
        if (ancillary_list)
            msg->msg_flags |= MSG_CTRUNC;
        msg->msg_controllen = 0;
    }

    unix_socket_ancillary_free_list(ancillary_list);
    return cnt;
}

int socket_poll(vfs_node_t *node, size_t events) {
    socket_handle_t *handler = node ? node->handle : NULL;
    if (!handler || !handler->sock)
        return EPOLLNVAL;
    socket_t *sock = handler->sock;
    int revents = 0;

    if (sock->connMax > 0) {
        // listen 模式
        mutex_lock(&sock->lock);
        if (sock->connCurr > 0)
            revents |= (events & EPOLLIN) ? EPOLLIN : 0;
        if (sock->connCurr < sock->connMax)
            revents |= (events & EPOLLOUT) ? EPOLLOUT : 0;
        if (sock->closed)
            revents |= EPOLLERR | EPOLLHUP;
        mutex_unlock(&sock->lock);
    } else if (unix_socket_is_dgram_type(sock->type)) {
        mutex_lock(&sock->lock);
        if ((events & EPOLLOUT) && !sock->closed && !sock->shut_wr &&
            sock->recv_pos < sock->recv_size)
            revents |= EPOLLOUT;

        if ((events & EPOLLIN) && sock->recv_pos > 0)
            revents |= EPOLLIN;
        if (sock->closed || sock->shut_rd)
            revents |= EPOLLERR | EPOLLHUP;

        mutex_unlock(&sock->lock);
    } else {
        mutex_lock(&sock->lock);
        socket_t *peer = sock->peer;
        if (peer) {
            if (peer->closed)
                revents |= EPOLLHUP;
            if ((events & EPOLLRDHUP) && (peer->closed || peer->shut_wr))
                revents |= EPOLLRDHUP;

            // 可写：对端有空间
            if ((events & EPOLLOUT) && !sock->shut_wr && !peer->closed &&
                peer->recv_pos < peer->recv_size)
                revents |= EPOLLOUT;

            // 可读：自己有数据
            if ((events & EPOLLIN) && (sock->recv_pos > 0 || sock->shut_rd ||
                                       peer->shut_wr || peer->closed))
                revents |= EPOLLIN;
        } else {
            if ((events & EPOLLIN) && sock->established)
                revents |= EPOLLIN;
            if ((events & EPOLLRDHUP) && sock->established)
                revents |= EPOLLRDHUP;
            if (sock->established || sock->closed || sock->shut_rd ||
                sock->shut_wr)
                revents |= EPOLLHUP;
            if (sock->closed)
                revents |= EPOLLERR;
        }
        mutex_unlock(&sock->lock);
    }

    return revents;
}

int socket_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    vfs_node_t *node = fd->node;
    socket_handle_t *handler = node ? node->handle : NULL;
    if (!handler || !handler->fd || !handler->sock)
        return -EBADF;

    socket_t *sock = handler->sock;

    switch (cmd) {
    case FIONREAD:
        if (!arg)
            return -EFAULT;
        {
            int value = (int)sock->recv_pos;
            if (copy_to_user((void *)arg, &value, sizeof(value)))
                return -EFAULT;
            return 0;
        }
    case FIONBIO:
        return 0;
    default:
        return -ENOTTY;
    }
}

bool socket_close(vfs_node_t *node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return true;

    socket_t *sock = handle->sock;
    socket_t *peer = NULL;

    // 标记关闭
    sock->closed = true;

    // 断开与对端的连接
    mutex_lock(&sock->lock);
    if (sock->connMax > 0 && sock->backlog && sock->connCurr > 0) {
        int pending = sock->connCurr;
        for (int i = 0; i < pending; i++) {
            int slot = (sock->connHead + i) % sock->connMax;
            socket_t *pending_sock = sock->backlog[slot];
            sock->backlog[slot] = NULL;
            if (!pending_sock)
                continue;

            socket_t *pending_peer = pending_sock->peer;
            pending_sock->peer = NULL;
            pending_sock->established = false;

            if (pending_peer && pending_peer->peer == pending_sock) {
                pending_peer->peer = NULL;
                socket_notify_sock(pending_peer,
                                   EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
            }
            socket_notify_sock(pending_sock,
                               EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
            unix_socket_free(pending_sock);
        }
        sock->connCurr = 0;
        sock->connHead = 0;
    }

    if (sock->peer) {
        peer = sock->peer;
        unix_socket_snapshot_peer_cred(sock, &peer->cred);
        unix_socket_snapshot_peer_cred(peer, &sock->cred);
        sock->peer->peer = NULL; // 对端不再指向我
        sock->peer = NULL;
    }
    mutex_unlock(&sock->lock);

    socket_notify_sock(sock, EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (peer) {
        socket_notify_sock(peer, EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    }

    unix_socket_free(sock);
    free(handle);

    return true;
}

ssize_t socket_read(fd_t *fd, void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = fd->node->handle;
    socket_t *sock = handle->sock;

    if (!unix_socket_is_dgram_type(sock->type) && !sock->peer &&
        !sock->established && sock->recv_pos == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, buf, limit, 0, fd);
}

ssize_t socket_write(fd_t *fd, const void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = fd->node->handle;
    socket_t *sock = handle->sock;

    if (!sock->peer) {
        if (unix_socket_is_dgram_type(sock->type))
            return -(EDESTADDRREQ);
        if (!unix_socket_is_dgram_type(sock->type) && sock->established) {
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -(EPIPE);
        }
        return -(ENOTCONN);
    }

    return unix_socket_send_to_peer(sock, sock->peer, buf, limit, 0, fd, NULL);
}

int unix_socket_pair(int domain, int type, int protocol, int *sv) {
    int sock_type = type & 0xF;
    if (!unix_socket_type_supported(sock_type)) {
        return -ESOCKTNOSUPPORT;
    }

    socket_t *sock1 = unix_socket_alloc();
    socket_t *sock2 = unix_socket_alloc();
    if (!sock1 || !sock2) {
        unix_socket_free(sock1);
        unix_socket_free(sock2);
        return -ENOMEM;
    }

    sock1->domain = domain;
    sock1->type = sock_type;
    sock1->protocol = protocol;

    sock2->domain = domain;
    sock2->type = sock_type;
    sock2->protocol = protocol;

    // 双向连接
    sock1->peer = sock2;
    sock2->peer = sock1;
    sock1->established = true;
    sock2->established = true;
    unix_socket_snapshot_peer_cred(sock1, &sock2->cred);
    unix_socket_snapshot_peer_cred(sock2, &sock1->cred);

    vfs_node_t *node1 = unix_socket_create_node(sock1);
    vfs_node_t *node2 = unix_socket_create_node(sock2);
    if (!node1 || !node2) {
        if (node1)
            vfs_free(node1);
        if (node2)
            vfs_free(node2);
        unix_socket_free(sock1);
        unix_socket_free(sock2);
        return -ENOMEM;
    }

    uint64_t flags = O_RDWR;
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

        fd_t *entry1 = fd_create(node1, O_RDWR | (flags & O_NONBLOCK),
                                 !!(type & O_CLOEXEC));
        fd_t *entry2 = fd_create(node2, O_RDWR | (flags & O_NONBLOCK),
                                 !!(type & O_CLOEXEC));
        if (!entry1 || !entry2) {
            if (entry1)
                fd_destroy(entry1);
            if (entry2)
                fd_destroy(entry2);
            ret = -ENOMEM;
            fd1 = fd2 = -1;
            break;
        }

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
            if (!newBuff) {
                mutex_unlock(&sock->lock);
                return -ENOMEM;
            }
            size_t preserved = MIN((size_t)new_size, sock->recv_pos);
            if (preserved) {
                unix_socket_recv_copy_out_locked(sock, 0, newBuff, preserved);
            }
            free_frames_bytes(sock->recv_buff, sock->recv_size);
            sock->recv_buff = newBuff;
            sock->recv_size = new_size;
            sock->recv_head = 0;
            sock->recv_pos = preserved;
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

    case SO_PEERCRED: {
        struct ucred peer_cred = {0};
        if (!unix_socket_get_peer_cred(sock, &peer_cred))
            return -ENOTCONN;
        if (*optlen < sizeof(struct ucred))
            return -EINVAL;
        memcpy(optval, &peer_cred, sizeof(struct ucred));
        *optlen = sizeof(struct ucred);
    } break;

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

static vfs_operations_t socket_vfs_ops = {
    .close = socket_close,
    .read = socket_read,
    .write = socket_write,
    .ioctl = socket_ioctl,
    .poll = socket_poll,
    .free_handle = vfs_generic_free_handle,
};

fs_t sockfs = {
    .name = "unix_socket",
    .magic = 0,
    .ops = &socket_vfs_ops,
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_HIDDEN,
};

void socketfs_init() {
    unix_socket_fsid = vfs_regist(&sockfs);
    spin_init(&unix_socket_list_lock);
    mutex_init(&unix_socket_bind_lock);
    memset(&first_unix_socket, 0, sizeof(socket_t));
    unix_socket_list_tail = &first_unix_socket;
    unix_socket_bind_map = HASHMAP_INIT;
    regist_socket(1, NULL, socket_socket, unix_socket_pair);
    netlink_init();
}
