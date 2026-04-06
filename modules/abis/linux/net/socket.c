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
#include <init/callbacks.h>

extern socket_op_t socket_ops;

typedef struct sockfs_info {
    spinlock_t lock;
    ino64_t next_ino;
} sockfs_info_t;

typedef struct sockfs_inode_info {
    struct vfs_inode vfs_inode;
} sockfs_inode_info_t;

static struct vfs_file_system_type sockfs_fs_type;
static const struct vfs_super_operations sockfs_super_ops;
static const struct vfs_file_operations sockfs_dir_file_ops;
static const struct vfs_file_operations sockfs_file_ops;
static mutex_t sockfs_mount_lock;
static struct vfs_mount *sockfs_internal_mnt;

socket_t first_unix_socket;
static socket_t *unix_socket_list_tail = &first_unix_socket;
spinlock_t unix_socket_list_lock;
static mutex_t unix_socket_bind_lock;

static hashmap_t unix_socket_bind_map = HASHMAP_INIT;

typedef struct unix_socket_bind_bucket {
    uint64_t hash;
    socket_t *head;
} unix_socket_bind_bucket_t;

static inline void socket_notify_sock(socket_t *sock, uint32_t events);
static inline void unix_socket_snapshot_peer_cred(socket_t *sock,
                                                  const struct ucred *cred);
void unix_socket_free(socket_t *sock);
static void unix_socket_handle_release(socket_handle_t *handle);
int socket_poll(vfs_node_t *node, size_t events);
int socket_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg);
ssize_t socket_read(fd_t *fd, void *buf, size_t offset, size_t limit);
ssize_t socket_write(fd_t *fd, const void *buf, size_t offset, size_t limit);

static inline sockfs_info_t *sockfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (sockfs_info_t *)sb->s_fs_info : NULL;
}

socket_handle_t *sockfs_inode_socket_handle(vfs_node_t *node) {
    return node ? (socket_handle_t *)node->i_private : NULL;
}

socket_handle_t *sockfs_file_handle(fd_t *file) {
    if (!file)
        return NULL;
    if (file->private_data)
        return (socket_handle_t *)file->private_data;
    return sockfs_inode_socket_handle(file->f_inode);
}

static inline socket_t *socket_file_sock(fd_t *file) {
    socket_handle_t *handle = sockfs_file_handle(file);
    return handle ? (socket_t *)handle->sock : NULL;
}

static struct vfs_inode *sockfs_alloc_inode(struct vfs_super_block *sb) {
    sockfs_inode_info_t *info = calloc(1, sizeof(*info));

    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void sockfs_destroy_inode(struct vfs_inode *inode) {
    socket_handle_t *handle;

    if (!inode)
        return;

    handle = sockfs_inode_socket_handle(inode);
    if (handle) {
        if (handle->release)
            handle->release(handle);
        else
            free(handle);
        inode->i_private = NULL;
    }

    free(container_of(inode, sockfs_inode_info_t, vfs_inode));
}

static void sockfs_put_super(struct vfs_super_block *sb) {
    if (sb && sb->s_fs_info)
        free(sb->s_fs_info);
}

static int sockfs_statfs(struct vfs_path *path, void *buf) {
    struct statfs *st = (struct statfs *)buf;
    struct vfs_super_block *sb;

    if (!path || !path->dentry || !path->dentry->d_inode || !st)
        return -EINVAL;

    memset(st, 0, sizeof(*st));
    sb = path->dentry->d_inode->i_sb;
    if (!sb)
        return 0;

    st->f_type = sb->s_magic;
    st->f_bsize = PAGE_SIZE;
    st->f_frsize = PAGE_SIZE;
    st->f_namelen = 255;
    st->f_flags = sb->s_flags;
    return 0;
}

static int sockfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int sockfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    sockfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *root;

    if (!fc)
        return -EINVAL;

    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb)
        return -ENOMEM;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    sb->s_magic = 0x736f636bULL;
    sb->s_fs_info = fsi;
    sb->s_op = &sockfs_super_ops;
    sb->s_type = &sockfs_fs_type;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->inode = 1;
    inode->i_mode = S_IFDIR | 0700;
    inode->type = file_dir;
    inode->i_nlink = 2;
    inode->i_fop = &sockfs_dir_file_ops;

    root = vfs_d_alloc(sb, NULL, NULL);
    if (!root) {
        vfs_iput(inode);
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root, inode);
    sb->s_root = root;
    fc->sb = sb;
    return 0;
}

static const struct vfs_super_operations sockfs_super_ops = {
    .alloc_inode = sockfs_alloc_inode,
    .destroy_inode = sockfs_destroy_inode,
    .put_super = sockfs_put_super,
    .statfs = sockfs_statfs,
};

static struct vfs_file_system_type sockfs_fs_type = {
    .name = "sockfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = sockfs_init_fs_context,
    .get_tree = sockfs_get_tree,
};

static struct vfs_mount *sockfs_get_internal_mount(void) {
    int ret;

    mutex_lock(&sockfs_mount_lock);
    if (!sockfs_internal_mnt) {
        ret = vfs_kern_mount("sockfs", 0, NULL, NULL, &sockfs_internal_mnt);
        if (ret < 0)
            sockfs_internal_mnt = NULL;
    }
    if (sockfs_internal_mnt)
        vfs_mntget(sockfs_internal_mnt);
    mutex_unlock(&sockfs_mount_lock);
    return sockfs_internal_mnt;
}

static ino64_t sockfs_next_ino(struct vfs_super_block *sb) {
    sockfs_info_t *fsi = sockfs_sb_info(sb);
    ino64_t ino;

    spin_lock(&fsi->lock);
    ino = ++fsi->next_ino;
    spin_unlock(&fsi->lock);
    return ino;
}

static loff_t sockfs_llseek(struct vfs_file *file, loff_t offset, int whence) {
    (void)file;
    (void)offset;
    (void)whence;
    return -ESPIPE;
}

static int sockfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    if (!file)
        return -EINVAL;
    file->private_data = inode ? inode->i_private : NULL;
    return 0;
}

static int sockfs_release(struct vfs_inode *inode, struct vfs_file *file) {
    (void)inode;
    if (!file)
        return 0;
    file->private_data = NULL;
    return 0;
}

static inline bool unix_socket_is_dgram_type(int type) {
    return type == SOCK_DGRAM;
}

static inline bool unix_socket_is_message_type(int type) {
    return type == SOCK_DGRAM || type == SOCK_SEQPACKET;
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
    (void)vfs_unlinkat(AT_FDCWD, path, 0);
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
    (void)sock;
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
    socket_handle_t *handle = sockfs_inode_socket_handle(node);
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

static bool unix_socket_backlog_reserve_locked(socket_t *sock,
                                               int min_capacity) {
    if (!sock || min_capacity <= 0)
        return true;

    if (sock->backlogCap >= min_capacity)
        return true;

    if (sock->connMax <= 0 || min_capacity > sock->connMax)
        return false;

    int new_capacity = sock->backlogCap;
    if (new_capacity <= 0)
        new_capacity = MIN(sock->connMax, 16);

    while (new_capacity < min_capacity) {
        if (new_capacity >= sock->connMax) {
            new_capacity = sock->connMax;
            break;
        }

        if (new_capacity > sock->connMax / 2) {
            new_capacity = sock->connMax;
        } else {
            new_capacity *= 2;
        }
    }

    if (new_capacity < min_capacity)
        return false;

    socket_t **new_backlog = calloc((size_t)new_capacity, sizeof(*new_backlog));
    if (!new_backlog)
        return false;

    for (int i = 0; i < sock->connCurr; i++) {
        int slot = (sock->connHead + i) % sock->backlogCap;
        new_backlog[i] = sock->backlog[slot];
    }

    free(sock->backlog);
    sock->backlog = new_backlog;
    sock->backlogCap = new_capacity;
    sock->connHead = 0;
    return true;
}

static inline size_t unix_socket_recv_used_locked(const socket_t *sock) {
    return sock ? skb_queue_bytes(&sock->recv_queue) : 0;
}

static inline size_t unix_socket_recv_space_locked(const socket_t *sock) {
    return sock ? skb_queue_space(&sock->recv_queue) : 0;
}

static inline size_t unix_socket_next_packet_len_locked(const socket_t *sock) {
    skb_buff_t *skb = NULL;

    if (!sock)
        return 0;

    skb = skb_queue_peek(&sock->recv_queue);
    return skb ? skb_unread_len(skb) : 0;
}

static void unix_socket_ancillary_free(unix_socket_ancillary_t *ancillary) {
    if (!ancillary)
        return;

    for (uint32_t i = 0; i < ancillary->file_count; i++) {
        if (ancillary->files[i])
            vfs_file_put(ancillary->files[i]);
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

static int unix_socket_ancillary_append(unix_socket_ancillary_t **head,
                                        unix_socket_ancillary_t **tail,
                                        unix_socket_ancillary_t *ancillary) {
    if (!ancillary)
        return 0;

    ancillary->next = NULL;
    if (*tail) {
        (*tail)->next = ancillary;
    } else {
        *head = ancillary;
    }
    *tail = ancillary;
    return 0;
}

static unix_socket_ancillary_t *
unix_socket_ancillary_clone_one(const unix_socket_ancillary_t *src) {
    if (!src)
        return NULL;

    unix_socket_ancillary_t *clone = calloc(1, sizeof(*clone));
    if (!clone)
        return NULL;

    clone->file_count = src->file_count;
    clone->cred = src->cred;
    clone->has_cred = src->has_cred;

    for (uint32_t i = 0; i < src->file_count; i++) {
        clone->files[i] = vfs_file_get(src->files[i]);
        if (!clone->files[i]) {
            unix_socket_ancillary_free(clone);
            return NULL;
        }
    }

    return clone;
}

static int unix_socket_collect_skb_ancillary(skb_buff_t *skb, bool peek,
                                             unix_socket_ancillary_t **head,
                                             unix_socket_ancillary_t **tail) {
    unix_socket_ancillary_t *ancillary = NULL;

    if (!skb || skb->offset != 0 || !skb->priv)
        return 0;

    if (peek) {
        ancillary = unix_socket_ancillary_clone_one(
            (unix_socket_ancillary_t *)skb->priv);
        if (!ancillary)
            return -ENOMEM;
    } else {
        ancillary = (unix_socket_ancillary_t *)skb_detach_priv(skb);
    }

    return unix_socket_ancillary_append(head, tail, ancillary);
}

static void unix_socket_drop_skb_ancillary(skb_buff_t *skb) {
    unix_socket_ancillary_t *ancillary = NULL;

    if (!skb || skb->offset != 0 || !skb->priv)
        return;

    ancillary = (unix_socket_ancillary_t *)skb_detach_priv(skb);
    unix_socket_ancillary_free(ancillary);
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

static size_t unix_socket_iov_copy_out(const struct iovec *iov, size_t iovlen,
                                       size_t dest_offset, const uint8_t *src,
                                       size_t len) {
    size_t copied = 0;
    size_t skipped = 0;

    if (!iov || !src || !len)
        return 0;

    for (size_t i = 0; i < iovlen && copied < len; i++) {
        if (!iov[i].iov_base || !iov[i].len)
            continue;

        if (dest_offset >= skipped + iov[i].len) {
            skipped += iov[i].len;
            continue;
        }

        size_t inner_off = 0;
        if (dest_offset > skipped)
            inner_off = dest_offset - skipped;

        size_t room = iov[i].len - inner_off;
        size_t copy_len = MIN(room, len - copied);
        memcpy((uint8_t *)iov[i].iov_base + inner_off, src + copied, copy_len);
        copied += copy_len;
        skipped += iov[i].len;
    }

    return copied;
}

static skb_buff_t *unix_socket_build_skb(const uint8_t *data, size_t len,
                                         unix_socket_ancillary_t *ancillary) {
    skb_buff_t *skb = skb_alloc(len);

    if (!skb) {
        unix_socket_ancillary_free(ancillary);
        return NULL;
    }

    if (len > 0 && data)
        memcpy(skb->data, data, len);
    skb->priv = ancillary;
    return skb;
}

static skb_buff_t *
unix_socket_build_skb_from_iov(const struct iovec *iov, size_t iovlen,
                               size_t total_len, unix_socket_ancillary_t *anc) {
    skb_buff_t *skb = skb_alloc(total_len);
    size_t copied = 0;

    if (!skb) {
        unix_socket_ancillary_free(anc);
        return NULL;
    }

    for (size_t i = 0; i < iovlen; i++) {
        if (!iov[i].iov_base || !iov[i].len)
            continue;
        memcpy(skb->data + copied, iov[i].iov_base, iov[i].len);
        copied += iov[i].len;
    }

    skb->priv = anc;
    return skb;
}

static size_t
unix_socket_stream_read_locked(socket_t *sock, uint8_t *out, size_t len,
                               bool peek,
                               unix_socket_ancillary_t **ancillary_head,
                               unix_socket_ancillary_t **ancillary_tail) {
    size_t copied = 0;
    skb_buff_t *skb = NULL;

    if (!sock || !len)
        return 0;

    for (skb = skb_queue_peek(&sock->recv_queue); skb && copied < len;) {
        size_t unread = skb_unread_len(skb);
        size_t chunk = MIN(len - copied, unread);
        if (!chunk)
            break;

        if (out)
            skb_copy_data(skb, 0, out + copied, chunk);

        if (ancillary_head && ancillary_tail) {
            if (unix_socket_collect_skb_ancillary(skb, peek, ancillary_head,
                                                  ancillary_tail) < 0)
                return (size_t)-ENOMEM;
        } else if (!peek) {
            unix_socket_drop_skb_ancillary(skb);
        }

        copied += chunk;

        if (peek) {
            skb = skb->next;
            continue;
        }

        sock->recv_queue.byte_count -= chunk;
        skb->offset += chunk;
        if (skb_unread_len(skb) == 0) {
            skb_buff_t *done = skb_queue_pop(&sock->recv_queue);
            skb_free(done, NULL);
        }

        skb = skb_queue_peek(&sock->recv_queue);
    }

    return copied;
}

static size_t
unix_socket_stream_readv_locked(socket_t *sock, const struct iovec *iov,
                                size_t iovlen, size_t len_total, bool peek,
                                unix_socket_ancillary_t **ancillary_head,
                                unix_socket_ancillary_t **ancillary_tail) {
    size_t copied = 0;
    skb_buff_t *skb = NULL;

    if (!sock || !iov || !iovlen || !len_total)
        return 0;

    for (skb = skb_queue_peek(&sock->recv_queue); skb && copied < len_total;) {
        size_t unread = skb_unread_len(skb);
        size_t chunk = MIN(len_total - copied, unread);
        if (!chunk)
            break;

        if (iov)
            unix_socket_iov_copy_out(iov, iovlen, copied,
                                     skb->data + skb->offset, chunk);

        if (ancillary_head && ancillary_tail) {
            if (unix_socket_collect_skb_ancillary(skb, peek, ancillary_head,
                                                  ancillary_tail) < 0)
                return (size_t)-ENOMEM;
        } else if (!peek) {
            unix_socket_drop_skb_ancillary(skb);
        }

        copied += chunk;

        if (peek) {
            skb = skb->next;
            continue;
        }

        sock->recv_queue.byte_count -= chunk;
        skb->offset += chunk;
        if (skb_unread_len(skb) == 0) {
            skb_buff_t *done = skb_queue_pop(&sock->recv_queue);
            skb_free(done, NULL);
        }

        skb = skb_queue_peek(&sock->recv_queue);
    }

    return copied;
}

static size_t unix_socket_packet_readv_locked(
    socket_t *sock, const struct iovec *iov, size_t iovlen, size_t len_total,
    bool peek, bool *truncated, unix_socket_ancillary_t **ancillary_head,
    unix_socket_ancillary_t **ancillary_tail) {
    skb_buff_t *skb = NULL;
    size_t packet_len = 0;
    size_t copied = 0;

    if (!sock || !iov || !iovlen)
        return 0;

    skb = skb_queue_peek(&sock->recv_queue);
    if (!skb)
        return 0;

    packet_len = skb_unread_len(skb);
    copied = MIN(len_total, packet_len);
    if (truncated)
        *truncated = packet_len > copied;

    if (copied > 0)
        unix_socket_iov_copy_out(iov, iovlen, 0, skb->data + skb->offset,
                                 copied);

    if (ancillary_head && ancillary_tail) {
        if (unix_socket_collect_skb_ancillary(skb, peek, ancillary_head,
                                              ancillary_tail) < 0)
            return (size_t)-ENOMEM;
    } else if (!peek) {
        unix_socket_drop_skb_ancillary(skb);
    }

    if (!peek) {
        skb_buff_t *done = skb_queue_pop(&sock->recv_queue);
        skb_free(done, NULL);
    }

    return copied;
}

static size_t
unix_socket_packet_read_locked(socket_t *sock, uint8_t *out, size_t len,
                               bool peek, bool *truncated,
                               unix_socket_ancillary_t **ancillary_head,
                               unix_socket_ancillary_t **ancillary_tail) {
    skb_buff_t *skb = NULL;
    size_t packet_len = 0;
    size_t copied = 0;

    if (!sock)
        return 0;

    skb = skb_queue_peek(&sock->recv_queue);
    if (!skb)
        return 0;

    packet_len = skb_unread_len(skb);
    copied = MIN(len, packet_len);
    if (truncated)
        *truncated = packet_len > copied;

    if (copied > 0 && out)
        skb_copy_data(skb, 0, out, copied);

    if (ancillary_head && ancillary_tail) {
        if (unix_socket_collect_skb_ancillary(skb, peek, ancillary_head,
                                              ancillary_tail) < 0)
            return (size_t)-ENOMEM;
    } else if (!peek) {
        unix_socket_drop_skb_ancillary(skb);
    }

    if (!peek) {
        skb_buff_t *done = skb_queue_pop(&sock->recv_queue);
        skb_free(done, NULL);
    }

    return copied;
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
                    vfs_file_get(current_task->fd_info->fds[send_fd]);
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

int sockfs_create_handle_file(socket_handle_t *handle, unsigned int open_flags,
                              struct vfs_file **out_file) {
    struct vfs_mount *mnt;
    struct vfs_super_block *sb;
    struct vfs_inode *inode;
    struct vfs_dentry *dentry;
    struct vfs_qstr name = {0};
    struct vfs_file *file;
    char label[64];

    if (!handle || !out_file)
        return -EINVAL;

    mnt = sockfs_get_internal_mount();
    if (!mnt)
        return -ENODEV;
    sb = mnt->mnt_sb;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    inode->i_ino = sockfs_next_ino(sb);
    inode->inode = inode->i_ino;
    inode->i_mode = S_IFSOCK | 0600;
    inode->type = file_socket;
    inode->i_nlink = 1;
    inode->i_fop = &sockfs_file_ops;
    inode->i_private = handle;

    snprintf(label, sizeof(label), "socket-%llu",
             (unsigned long long)inode->i_ino);
    vfs_qstr_make(&name, label);
    dentry = vfs_d_alloc(sb, sb->s_root, &name);
    if (!dentry) {
        inode->i_private = NULL;
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    vfs_d_instantiate(dentry, inode);
    file = vfs_alloc_file(&(struct vfs_path){.mnt = mnt, .dentry = dentry},
                          open_flags);
    if (!file) {
        vfs_dput(dentry);
        inode->i_private = NULL;
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    file->private_data = handle;
    *out_file = file;

    vfs_dput(dentry);
    vfs_iput(inode);
    vfs_mntput(mnt);
    return 0;
}

socket_t *unix_socket_alloc() {
    socket_t *sock = malloc(sizeof(socket_t));
    if (!sock)
        return NULL;
    memset(sock, 0, sizeof(socket_t));
    mutex_init(&sock->lock);

    sock->recv_size = BUFFER_SIZE;
    skb_queue_init(&sock->recv_queue, sock->recv_size,
                   (skb_priv_destructor_t)unix_socket_ancillary_free);
    sock->node = NULL;

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
    skb_queue_purge(&sock->recv_queue);
    if (sock->bindAddr)
        free(sock->bindAddr);
    if (sock->filename)
        free(sock->filename);
    if (sock->backlog)
        free(sock->backlog);
    if (sock->filter)
        free(sock->filter);

    free(sock);
}

static void unix_socket_handle_release(socket_handle_t *handle) {
    socket_t *sock;
    socket_t *peer = NULL;

    if (!handle)
        return;

    sock = (socket_t *)handle->sock;
    if (!sock) {
        free(handle);
        return;
    }

    mutex_lock(&sock->lock);
    sock->closed = true;
    sock->node = NULL;
    if (sock->connMax > 0 && sock->backlogCap > 0 && sock->connCurr > 0) {
        int pending = sock->connCurr;
        for (int i = 0; i < pending; i++) {
            int slot = (sock->connHead + i) % sock->backlogCap;
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
        sock->peer->peer = NULL;
        sock->peer = NULL;
    }
    mutex_unlock(&sock->lock);

    socket_notify_sock(sock, EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (peer)
        socket_notify_sock(peer, EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR);

    unix_socket_free(sock);
    free(handle);
}

static size_t unix_socket_send_stream_to_peer(
    socket_t *self, socket_t *peer, const uint8_t *data, size_t len, int flags,
    fd_t *fd_handle, unix_socket_ancillary_t **ancillary) {
    socket_t *active_peer = peer;

    if (!len)
        return 0;

    while (true) {
        if (self && self->shut_wr) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }

        if (self && unix_socket_is_connected_type(self->type))
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
            size_t to_copy = MIN(len, available);
            unix_socket_ancillary_t *skb_ancillary = NULL;
            skb_buff_t *skb = NULL;

            if (ancillary && *ancillary) {
                skb_ancillary = *ancillary;
                *ancillary = NULL;
            }

            skb = unix_socket_build_skb(data, to_copy, skb_ancillary);
            if (!skb) {
                mutex_unlock(&active_peer->lock);
                return -ENOMEM;
            }
            if (!skb_queue_push(&active_peer->recv_queue, skb)) {
                skb_free(skb,
                         (skb_priv_destructor_t)unix_socket_ancillary_free);
                mutex_unlock(&active_peer->lock);
                continue;
            }

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
        if (self && unix_socket_is_connected_type(self->type) && self->node)
            wait_node = self->node;
        if (!wait_node && active_peer->node)
            wait_node = active_peer->node;
        if (!wait_node)
            return -EINVAL;

        int reason = socket_wait_node(wait_node, EPOLLOUT, "socket_send");
        if (reason != EOK)
            return -EINTR;
    }
}

static size_t unix_socket_send_skb_to_peer(socket_t *self, socket_t *peer,
                                           skb_buff_t *skb, int flags,
                                           fd_t *fd_handle) {
    socket_t *active_peer = peer;
    size_t packet_len = skb ? skb_unread_len(skb) : 0;

    if (!skb)
        return -EINVAL;

    while (true) {
        if (self && self->shut_wr) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EPIPE;
        }

        if (self && unix_socket_is_connected_type(self->type))
            active_peer = self->peer;
        if (!active_peer) {
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EPIPE;
        }

        mutex_lock(&active_peer->lock);
        if (active_peer->closed || active_peer->shut_rd) {
            mutex_unlock(&active_peer->lock);
            if (!(flags & MSG_NOSIGNAL))
                task_commit_signal(current_task, SIGPIPE, NULL);
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EPIPE;
        }

        if (packet_len > active_peer->recv_size) {
            mutex_unlock(&active_peer->lock);
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EMSGSIZE;
        }

        if (unix_socket_recv_space_locked(active_peer) >= packet_len) {
            if (!skb_queue_push(&active_peer->recv_queue, skb)) {
                mutex_unlock(&active_peer->lock);
                continue;
            }

            mutex_unlock(&active_peer->lock);
            socket_notify_sock(active_peer, EPOLLIN);
            return packet_len;
        }
        mutex_unlock(&active_peer->lock);

        if ((fd_handle && (fd_get_flags(fd_handle) & O_NONBLOCK)) ||
            (flags & MSG_DONTWAIT)) {
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -(EWOULDBLOCK);
        }

        vfs_node_t *wait_node = NULL;
        if (self && unix_socket_is_connected_type(self->type) && self->node)
            wait_node = self->node;
        if (!wait_node && active_peer->node)
            wait_node = active_peer->node;
        if (!wait_node) {
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EINVAL;
        }

        int reason = socket_wait_node(wait_node, EPOLLOUT, "socket_send");
        if (reason != EOK) {
            skb_free(skb, (skb_priv_destructor_t)unix_socket_ancillary_free);
            return -EINTR;
        }
    }
}

static size_t unix_socket_send_to_peer(socket_t *self, socket_t *peer,
                                       const uint8_t *data, size_t len,
                                       int flags, fd_t *fd_handle,
                                       unix_socket_ancillary_t **ancillary) {
    if (self && unix_socket_is_message_type(self->type)) {
        unix_socket_ancillary_t *skb_ancillary = NULL;
        skb_buff_t *skb = NULL;

        if (ancillary && *ancillary) {
            skb_ancillary = *ancillary;
            *ancillary = NULL;
        }

        skb = unix_socket_build_skb(data, len, skb_ancillary);
        if (!skb)
            return -ENOMEM;

        return unix_socket_send_skb_to_peer(self, peer, skb, flags, fd_handle);
    }

    return unix_socket_send_stream_to_peer(self, peer, data, len, flags,
                                           fd_handle, ancillary);
}

static size_t unix_socket_recv_from_self(socket_t *self, socket_t *peer,
                                         uint8_t *buf, size_t len, int flags,
                                         fd_t *fd_handle) {
    bool peek = !!(flags & MSG_PEEK);

    if (!self)
        return -EINVAL;
    if (self->shut_rd)
        return 0;
    if (!len && !unix_socket_is_message_type(self->type))
        return 0;

    while (true) {
        mutex_lock(&self->lock);

        bool has_data = unix_socket_is_message_type(self->type)
                            ? (skb_queue_packets(&self->recv_queue) > 0)
                            : (unix_socket_recv_used_locked(self) > 0);
        if (has_data) {
            bool truncated = false;
            size_t copied =
                unix_socket_is_message_type(self->type)
                    ? unix_socket_packet_read_locked(self, buf, len, peek,
                                                     &truncated, NULL, NULL)
                    : unix_socket_stream_read_locked(self, buf, len, peek, NULL,
                                                     NULL);
            mutex_unlock(&self->lock);

            if (!peek) {
                socket_notify_sock(self, EPOLLOUT);
                if (self->peer)
                    socket_notify_sock(self->peer, EPOLLOUT);
            }
            return copied;
        }

        socket_t *active_peer = peer;
        if (unix_socket_is_connected_type(self->type))
            active_peer = self->peer;
        bool eof =
            unix_socket_is_connected_type(self->type) &&
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
        int reason = socket_wait_node(self->node, EPOLLIN, "socket_recv");
        if (reason != EOK)
            return -EINTR;
    }
}

static size_t
unix_socket_recvmsg_from_self(socket_t *self, socket_t *peer,
                              struct msghdr *msg, int flags, fd_t *fd_handle,
                              unix_socket_ancillary_t **ancillary_out) {
    bool peek = !!(flags & MSG_PEEK);
    size_t len_total = 0;

    if (!self || !msg)
        return -EINVAL;
    if (ancillary_out)
        *ancillary_out = NULL;
    if (self->shut_rd)
        return 0;

    len_total = unix_socket_iov_total_len(msg->msg_iov, msg->msg_iovlen);
    if (!len_total && !unix_socket_is_message_type(self->type))
        return 0;

    while (true) {
        mutex_lock(&self->lock);

        bool has_data = unix_socket_is_message_type(self->type)
                            ? (skb_queue_packets(&self->recv_queue) > 0)
                            : (unix_socket_recv_used_locked(self) > 0);
        if (has_data) {
            unix_socket_ancillary_t *ancillary_list = NULL;
            unix_socket_ancillary_t *ancillary_tail = NULL;
            bool truncated = false;
            size_t copied = 0;

            if (unix_socket_is_message_type(self->type)) {
                if (len_total > 0) {
                    copied = unix_socket_packet_readv_locked(
                        self, msg->msg_iov, msg->msg_iovlen, len_total, peek,
                        &truncated, &ancillary_list, &ancillary_tail);
                } else {
                    copied = unix_socket_packet_read_locked(
                        self, NULL, 0, peek, &truncated, &ancillary_list,
                        &ancillary_tail);
                }
            } else {
                copied = unix_socket_stream_readv_locked(
                    self, msg->msg_iov, msg->msg_iovlen, len_total, peek,
                    &ancillary_list, &ancillary_tail);
            }
            mutex_unlock(&self->lock);

            if ((ssize_t)copied < 0) {
                unix_socket_ancillary_free_list(ancillary_list);
                return copied;
            }

            if (truncated)
                msg->msg_flags |= MSG_TRUNC;
            if (ancillary_out)
                *ancillary_out = ancillary_list;
            else
                unix_socket_ancillary_free_list(ancillary_list);

            if (!peek) {
                socket_notify_sock(self, EPOLLOUT);
                if (self->peer)
                    socket_notify_sock(self->peer, EPOLLOUT);
            }
            return copied;
        }

        socket_t *active_peer = peer;
        if (unix_socket_is_connected_type(self->type))
            active_peer = self->peer;
        bool eof =
            unix_socket_is_connected_type(self->type) &&
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
    vfs_file_put(pending_file);
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

            fd_t *new_entry = vfs_file_get(pending_files[i]);
            if (!new_entry)
                break;
            new_entry->close_on_exec = !!(recv_flags & MSG_CMSG_CLOEXEC);
            current_task->fd_info->fds[new_fd] = new_entry;
            fds_out[installed++] = new_fd;
        }
    });

    for (size_t i = 0; i < installed; i++) {
        vfs_file_put(pending_files[i]);
        pending_files[i] = NULL;
        on_open_file_call(current_task, fds_out[i]);
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

    struct vfs_file *file = NULL;
    socket_handle_t *handle = calloc(1, sizeof(*handle));
    uint64_t flags = O_RDWR;
    if (type & O_NONBLOCK)
        flags |= O_NONBLOCK;

    if (!handle) {
        unix_socket_free(sock);
        return -ENOMEM;
    }
    handle->op = &socket_ops;
    handle->sock = sock;
    handle->read_op = socket_read;
    handle->write_op = socket_write;
    handle->ioctl_op = socket_ioctl;
    handle->poll_op = socket_poll;
    handle->release = unix_socket_handle_release;

    int ret = sockfs_create_handle_file(handle, flags, &file);
    if (ret < 0) {
        free(handle);
        unix_socket_free(sock);
        return ret;
    }
    sock->node = file->f_inode;

    ret = task_install_file(current_task, file,
                            (type & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(file);
    return ret;
}

int socket_bind(uint64_t fd, const struct sockaddr_un *addr,
                socklen_t addrlen) {
    if (!addr)
        return -EFAULT;

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    socket_t *sock = handle->sock;

    if (sock->bindAddr)
        return -EINVAL;

    char *safe = unix_socket_addr_safe(addr, addrlen);
    if (((uint64_t)safe & ERRNO_MASK) == ERRNO_MASK)
        return (uint64_t)safe;

    bool is_abstract = (addr->sun_path[0] == '\0');
    size_t safeLen = strlen(safe);

    if (!is_abstract) {
        struct vfs_path existing = {0};
        if (vfs_filename_lookup(AT_FDCWD, safe, LOOKUP_FOLLOW, &existing) ==
            0) {
            vfs_path_put(&existing);
            free(safe);
            return -EADDRINUSE;
        }
        int mkret = vfs_mknodat(AT_FDCWD, safe, S_IFSOCK | 0666, 0);
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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    socket_t *sock = handle->sock;

    mutex_lock(&sock->lock);
    unix_socket_fill_cred_from_task(&sock->cred, current_task);
    if (sock->backlog) {
        free(sock->backlog);
        sock->backlog = NULL;
    }
    sock->connMax = backlog;
    sock->connCurr = 0;
    sock->connHead = 0;
    sock->backlogCap = 0;
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
            listener_fd = vfs_file_get(current_task->fd_info->fds[fd]);
        }
    });
    if (!listener_fd) {
        return -EBADF;
    }

    socket_handle_t *handle = sockfs_file_handle(listener_fd);
    socket_t *listen_sock = handle->sock;

    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
        vfs_file_put(listener_fd);
        return -EINVAL;
    }

    if (addr && !addrlen) {
        vfs_file_put(listener_fd);
        return -EFAULT;
    }

    bool listener_nonblock = !!(fd_get_flags(listener_fd) & O_NONBLOCK);

    if (!listen_sock->connMax) {
        vfs_file_put(listener_fd);
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
                (listen_sock->connHead + 1) % listen_sock->backlogCap;
            listen_sock->connCurr--;
            if (listen_sock->connCurr == 0)
                listen_sock->connHead = 0;
            mutex_unlock(&listen_sock->lock);
            socket_notify_sock(listen_sock, EPOLLOUT);
            break;
        }
        mutex_unlock(&listen_sock->lock);
        if (fd_get_flags(listener_fd) & O_NONBLOCK) {
            vfs_file_put(listener_fd);
            return -(EWOULDBLOCK);
        }
        int reason =
            socket_wait_node(listener_fd->node, EPOLLIN, "socket_accept");
        if (reason != EOK) {
            vfs_file_put(listener_fd);
            return -EINTR;
        }
    }

    if (!server_sock) {
        vfs_file_put(listener_fd);
        return -ECONNABORTED;
    }

    struct vfs_file *accept_file = NULL;
    uint64_t accept_file_flags = O_RDWR;
    if ((flags & O_NONBLOCK) || listener_nonblock)
        accept_file_flags |= O_NONBLOCK;

    socket_handle_t *accept_handle = calloc(1, sizeof(*accept_handle));
    if (!accept_handle) {
        vfs_file_put(listener_fd);
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
            socket_notify_sock(server_sock->peer,
                               EPOLLERR | EPOLLHUP | EPOLLRDHUP);
        }
        unix_socket_free(server_sock);
        return -ENOMEM;
    }
    accept_handle->op = &socket_ops;
    accept_handle->sock = server_sock;
    accept_handle->read_op = socket_read;
    accept_handle->write_op = socket_write;
    accept_handle->ioctl_op = socket_ioctl;
    accept_handle->poll_op = socket_poll;
    accept_handle->release = unix_socket_handle_release;

    if (sockfs_create_handle_file(accept_handle, accept_file_flags,
                                  &accept_file) < 0) {
        free(accept_handle);
        vfs_file_put(listener_fd);
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
            socket_notify_sock(server_sock->peer,
                               EPOLLERR | EPOLLHUP | EPOLLRDHUP);
        }
        unix_socket_free(server_sock);
        return -ENOMEM;
    }
    server_sock->node = accept_file->f_inode;

    int ret = task_install_file(current_task, accept_file,
                                (flags & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(listener_fd);
    vfs_file_put(accept_file);

    if (ret < 0) {
        if (server_sock->peer) {
            server_sock->peer->peer = NULL;
            server_sock->peer->established = false;
            socket_notify_sock(server_sock->peer,
                               EPOLLERR | EPOLLHUP | EPOLLRDHUP);
        }
        unix_socket_free(server_sock);
        return ret;
    }

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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
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
            struct vfs_path path_node = {0};
            if (vfs_filename_lookup(AT_FDCWD, safe, LOOKUP_FOLLOW,
                                    &path_node) == 0) {
                ret = -ECONNREFUSED;
                vfs_path_put(&path_node);
            }
        }
        free(safe);
        return ret;
    }
    free(safe);

    while (true) {
        mutex_lock(&listen_sock->lock);
        if (listen_sock->closed || !listen_sock->connMax) {
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
    if (listen_sock->closed || !listen_sock->connMax ||
        listen_sock->connCurr >= listen_sock->connMax) {
        mutex_unlock(&listen_sock->lock);
        sock->peer = NULL;
        sock->established = false;
        server_sock->peer = NULL;
        unix_socket_release_lookup_ref(listen_sock);
        unix_socket_free(server_sock);
        return -ECONNREFUSED;
    }
    if (!unix_socket_backlog_reserve_locked(listen_sock,
                                            listen_sock->connCurr + 1)) {
        mutex_unlock(&listen_sock->lock);
        sock->peer = NULL;
        sock->established = false;
        server_sock->peer = NULL;
        unix_socket_release_lookup_ref(listen_sock);
        unix_socket_free(server_sock);
        return -ENOMEM;
    }
    int tail = (listen_sock->connHead + listen_sock->connCurr) %
               listen_sock->backlogCap;
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
    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;
    bool peer_needs_unref = false;

    if (!peer) {
        if (unix_socket_is_connected_type(sock->type) && sock->established) {
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
    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;

    if (unix_socket_is_connected_type(sock->type) && !sock->peer &&
        !sock->established && unix_socket_recv_used_locked(sock) == 0 &&
        skb_queue_packets(&sock->recv_queue) == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, out, limit, flags,
                                      caller_fd);
}

size_t unix_socket_sendmsg(uint64_t fd, const struct msghdr *msg, int flags) {
    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    socket_t *peer = sock->peer;
    bool peer_needs_unref = false;

    if (!peer) {
        if (unix_socket_is_connected_type(sock->type) && sock->established) {
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

    bool peer_passcred = false;
    if (peer) {
        if (peer_needs_unref) {
            if (mutex_trylock(&peer->lock)) {
                peer_passcred = peer->passcred;
                mutex_unlock(&peer->lock);
            }
        } else {
            socket_t *p = sock->peer;
            if (p && mutex_trylock(&p->lock)) {
                peer_passcred = p->passcred;
                mutex_unlock(&p->lock);
            }
        }
    }

    if (peer_passcred) {
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

    if (unix_socket_is_message_type(sock->type)) {
        skb_buff_t *skb = unix_socket_build_skb_from_iov(
            msg->msg_iov, msg->msg_iovlen, total_len, ancillary);
        size_t ret = 0;

        if (!skb) {
            if (peer_needs_unref)
                unix_socket_release_lookup_ref(peer);
            return -ENOMEM;
        }

        ret = unix_socket_send_skb_to_peer(sock, peer, skb, flags, caller_fd);
        if (peer_needs_unref)
            unix_socket_release_lookup_ref(peer);
        return ret;
    }

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
                if (cnt > 0)
                    return cnt;
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
    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    fd_t *caller_fd = current_task->fd_info->fds[fd];
    socket_t *sock = handle->sock;
    if (unix_socket_is_connected_type(sock->type) && !sock->peer &&
        !sock->established && unix_socket_recv_used_locked(sock) == 0 &&
        skb_queue_packets(&sock->recv_queue) == 0)
        return (size_t)-ENOTCONN;

    msg->msg_flags = 0;
    unix_socket_ancillary_t *ancillary_list = NULL;
    size_t cnt = unix_socket_recvmsg_from_self(sock, NULL, msg, flags,
                                               caller_fd, &ancillary_list);
    if ((int64_t)cnt < 0)
        return cnt;

    if (ancillary_list && msg->msg_control &&
        msg->msg_controllen >= sizeof(struct cmsghdr)) {
        size_t controllen_used = 0;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
        bool emitted_cred = false;

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
                if (emitted_cred) {
                    continue;
                }

                size_t space_left = msg->msg_controllen - controllen_used;
                if (cmsg && space_left >= CMSG_SPACE(sizeof(struct ucred))) {
                    cmsg->cmsg_level = SOL_SOCKET;
                    cmsg->cmsg_type = SCM_CREDENTIALS;
                    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                    memcpy(CMSG_DATA(cmsg), &anc->cred, sizeof(struct ucred));
                    controllen_used += CMSG_SPACE(sizeof(struct ucred));
                    cmsg = CMSG_NXTHDR(msg, cmsg);
                    emitted_cred = true;
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
    socket_handle_t *handler = sockfs_inode_socket_handle(node);
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
        if ((events & EPOLLOUT) && !sock->closed && !sock->shut_wr)
            revents |= EPOLLOUT;

        if ((events & EPOLLIN) && skb_queue_packets(&sock->recv_queue) > 0)
            revents |= EPOLLIN;
        if (sock->closed || sock->shut_rd)
            revents |= EPOLLERR | EPOLLHUP;

        mutex_unlock(&sock->lock);
    } else {
        mutex_lock(&sock->lock);
        socket_t *peer = sock->peer;
        if (peer) {
            if (mutex_trylock(&peer->lock)) {
                if (peer->closed)
                    revents |= EPOLLHUP;
                if ((events & EPOLLRDHUP) && (peer->closed || peer->shut_wr))
                    revents |= EPOLLRDHUP;
                if ((events & EPOLLOUT) && !sock->shut_wr && !peer->closed &&
                    unix_socket_recv_space_locked(peer) > 0)
                    revents |= EPOLLOUT;

                bool has_input =
                    unix_socket_is_message_type(sock->type)
                        ? (skb_queue_packets(&sock->recv_queue) > 0)
                        : (unix_socket_recv_used_locked(sock) > 0);
                if ((events & EPOLLIN) && (has_input || sock->shut_rd ||
                                           peer->shut_wr || peer->closed))
                    revents |= EPOLLIN;
                mutex_unlock(&peer->lock);
            } else {
                bool has_input =
                    unix_socket_is_message_type(sock->type)
                        ? (skb_queue_packets(&sock->recv_queue) > 0)
                        : (unix_socket_recv_used_locked(sock) > 0);
                if ((events & EPOLLIN) && has_input)
                    revents |= EPOLLIN;
                if (sock->closed || peer->closed)
                    revents |= EPOLLHUP | EPOLLERR;
            }
            mutex_unlock(&sock->lock);
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
            mutex_unlock(&sock->lock);
        }
    }

    return revents;
}

int socket_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    vfs_node_t *node = fd->node;
    socket_handle_t *handler = sockfs_file_handle(fd);
    if (!handler || !handler->sock)
        return -EBADF;

    socket_t *sock = handler->sock;

    switch (cmd) {
    case FIONREAD:
        if (!arg)
            return -EFAULT;
        {
            mutex_lock(&sock->lock);
            int value = (int)(unix_socket_is_message_type(sock->type)
                                  ? unix_socket_next_packet_len_locked(sock)
                                  : unix_socket_recv_used_locked(sock));
            mutex_unlock(&sock->lock);
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

ssize_t socket_read(fd_t *fd, void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = sockfs_file_handle(fd);
    socket_t *sock = handle->sock;

    if (unix_socket_is_connected_type(sock->type) && !sock->peer &&
        !sock->established && unix_socket_recv_used_locked(sock) == 0 &&
        skb_queue_packets(&sock->recv_queue) == 0)
        return -(ENOTCONN);

    return unix_socket_recv_from_self(sock, sock->peer, buf, limit, 0, fd);
}

ssize_t socket_write(fd_t *fd, const void *buf, size_t offset, size_t limit) {
    socket_handle_t *handle = sockfs_file_handle(fd);
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

    uint64_t flags = O_RDWR;
    if (type & O_NONBLOCK)
        flags |= O_NONBLOCK;

    struct vfs_file *file1 = NULL;
    struct vfs_file *file2 = NULL;
    socket_handle_t *handle1 = calloc(1, sizeof(*handle1));
    socket_handle_t *handle2 = calloc(1, sizeof(*handle2));
    if (!handle1 || !handle2) {
        free(handle1);
        free(handle2);
        sock1->peer = NULL;
        sock2->peer = NULL;
        sock1->established = false;
        sock2->established = false;
        unix_socket_free(sock1);
        unix_socket_free(sock2);
        return -ENOMEM;
    }
    handle1->op = &socket_ops;
    handle1->sock = sock1;
    handle1->read_op = socket_read;
    handle1->write_op = socket_write;
    handle1->ioctl_op = socket_ioctl;
    handle1->poll_op = socket_poll;
    handle1->release = unix_socket_handle_release;
    handle2->op = &socket_ops;
    handle2->sock = sock2;
    handle2->read_op = socket_read;
    handle2->write_op = socket_write;
    handle2->ioctl_op = socket_ioctl;
    handle2->poll_op = socket_poll;
    handle2->release = unix_socket_handle_release;

    if (sockfs_create_handle_file(handle1, flags, &file1) < 0 ||
        sockfs_create_handle_file(handle2, flags, &file2) < 0) {
        free(handle1);
        free(handle2);
        sock1->peer = NULL;
        sock2->peer = NULL;
        sock1->established = false;
        sock2->established = false;
        if (file1)
            vfs_file_put(file1);
        if (file2)
            vfs_file_put(file2);
        unix_socket_free(sock1);
        unix_socket_free(sock2);
        return -ENOMEM;
    }
    sock1->node = file1->f_inode;
    sock2->node = file2->f_inode;

    int fd1 = -1, fd2 = -1;
    int ret = task_install_file(current_task, file1,
                                (type & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    if (ret >= 0)
        fd1 = ret;
    if (ret >= 0)
        ret = task_install_file(current_task, file2,
                                (type & O_CLOEXEC) ? FD_CLOEXEC : 0, fd1 + 1);
    if (ret >= 0)
        fd2 = ret;

    vfs_file_put(file1);
    vfs_file_put(file2);

    if (ret < 0 || fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0)
            task_close_file_descriptor(current_task, fd1);
        unix_socket_free(sock1);
        unix_socket_free(sock2);
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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
    socket_t *sock = handle->sock;

    unix_socket_write_sockaddr(unix_socket_local_name(sock), addr, addrlen);

    return 0;
}

size_t unix_socket_getpeername(uint64_t fd, struct sockaddr_un *addr,
                               socklen_t *len) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return (size_t)-EBADF;

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
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
            sock->recv_size = new_size;
            skb_queue_set_limit(&sock->recv_queue, sock->recv_size);
            mutex_unlock(&sock->lock);
        }
        break;

    case SO_PASSCRED:
        if (optlen < sizeof(int))
            return -EINVAL;
        sock->passcred = *(int *)optval;
        break;

    case SO_PRIORITY:
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

    socket_handle_t *handle =
        sockfs_file_handle(current_task->fd_info->fds[fd]);
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

static ssize_t sockfs_read(struct vfs_file *file, void *buf, size_t count,
                           loff_t *ppos) {
    socket_handle_t *handle = sockfs_file_handle(file);

    (void)ppos;
    if (!handle || !handle->read_op)
        return -EINVAL;
    return handle->read_op(file, buf, 0, count);
}

static ssize_t sockfs_write(struct vfs_file *file, const void *buf,
                            size_t count, loff_t *ppos) {
    socket_handle_t *handle = sockfs_file_handle(file);

    (void)ppos;
    if (!handle || !handle->write_op)
        return -EINVAL;
    return handle->write_op(file, buf, 0, count);
}

static long sockfs_ioctl(struct vfs_file *file, unsigned long cmd,
                         unsigned long arg) {
    socket_handle_t *handle = sockfs_file_handle(file);

    if (!handle || !handle->ioctl_op)
        return -EINVAL;
    return handle->ioctl_op(file, (ssize_t)cmd, (ssize_t)arg);
}

static __poll_t sockfs_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    socket_handle_t *handle = sockfs_file_handle(file);

    (void)pt;
    if (!handle || !handle->poll_op)
        return EPOLLNVAL;
    return handle->poll_op(file ? file->f_inode : NULL,
                           EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLRDHUP);
}

static const struct vfs_file_operations sockfs_dir_file_ops = {
    .llseek = sockfs_llseek,
    .open = sockfs_open,
    .release = sockfs_release,
};

static const struct vfs_file_operations sockfs_file_ops = {
    .llseek = sockfs_llseek,
    .read = sockfs_read,
    .write = sockfs_write,
    .unlocked_ioctl = sockfs_ioctl,
    .poll = sockfs_poll,
    .open = sockfs_open,
    .release = sockfs_release,
};

void socketfs_init() {
    mutex_init(&sockfs_mount_lock);
    vfs_register_filesystem(&sockfs_fs_type);
    spin_init(&unix_socket_list_lock);
    mutex_init(&unix_socket_bind_lock);
    memset(&first_unix_socket, 0, sizeof(socket_t));
    unix_socket_list_tail = &first_unix_socket;
    unix_socket_bind_map = HASHMAP_INIT;
    regist_socket(1, NULL, socket_socket, unix_socket_pair);
    netlink_init();
}
