#include <arch/arch.h>
#include <net/net_syscall.h>
#include <net/real_socket.h>
#include <net/socket.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <drivers/kernel_logger.h>
#include <net/netlink.h>

#define SOCKET_MMSG_VLEN_MAX 1024U
#define SOCKET_IOV_MAX 1024U

static bool is_socket(fd_t *fd) {
    if (!(fd->node->type & file_socket))
        return false;
    return true;
}

static int socket_validate_user_buffer(const void *ptr, size_t len) {
    if (!len)
        return 0;
    if (!ptr || check_user_overflow((uint64_t)ptr, len))
        return -EFAULT;
    return 0;
}

static int socket_validate_user_mapped_buffer(const void *ptr, size_t len) {
    if (!len)
        return 0;
    if (!ptr || check_user_overflow((uint64_t)ptr, len) ||
        check_unmapped((uint64_t)ptr, len))
        return -EFAULT;
    return 0;
}

static int socket_alloc_copy_from_user(const void *user_ptr, size_t len,
                                       void **out_buf) {
    int ret = socket_validate_user_buffer(user_ptr, len);
    if (ret < 0)
        return ret;

    if (!len) {
        *out_buf = NULL;
        return 0;
    }

    void *buf = malloc(len);
    if (!buf)
        return -ENOMEM;
    if (copy_from_user(buf, user_ptr, len)) {
        free(buf);
        return -EFAULT;
    }

    *out_buf = buf;
    return 0;
}

static int socket_copy_sockaddr_from_user(const struct sockaddr_un *user_addr,
                                          socklen_t addrlen,
                                          struct sockaddr_un **out_addr) {
    return socket_alloc_copy_from_user(user_addr, addrlen, (void **)out_addr);
}

static int socket_validate_user_struct(const void *ptr, size_t len) {
    if (!ptr || check_user_overflow((uint64_t)ptr, len) ||
        check_unmapped((uint64_t)ptr, len))
        return -EFAULT;
    return 0;
}

static int socket_validate_mmsg_array(const struct mmsghdr *msgvec,
                                      unsigned int vlen) {
    if (!vlen || vlen > SOCKET_MMSG_VLEN_MAX)
        return -EINVAL;

    return socket_validate_user_struct(msgvec,
                                       (size_t)vlen * sizeof(struct mmsghdr));
}

static void socket_release_iov_copy(struct iovec *iov) {
    if (iov)
        free(iov);
}

static int socket_copy_msghdr_from_user(const struct msghdr *user_msg,
                                        struct msghdr *kernel_msg,
                                        struct msghdr *user_shadow,
                                        struct iovec **kernel_iov_out) {
    if (!kernel_msg || !user_shadow || !kernel_iov_out)
        return -EINVAL;

    *kernel_iov_out = NULL;
    memset(kernel_msg, 0, sizeof(*kernel_msg));
    memset(user_shadow, 0, sizeof(*user_shadow));

    int ret = socket_validate_user_struct(user_msg, sizeof(*user_msg));
    if (ret < 0)
        return ret;

    if (copy_from_user(user_shadow, user_msg, sizeof(*user_shadow)))
        return -EFAULT;

    if (user_shadow->msg_iovlen > SOCKET_IOV_MAX)
        return -EMSGSIZE;

    if (user_shadow->msg_iovlen > 0) {
        if (!user_shadow->msg_iov)
            return -EFAULT;
        if (user_shadow->msg_iovlen > SIZE_MAX / sizeof(struct iovec))
            return -EINVAL;

        size_t iov_bytes = user_shadow->msg_iovlen * sizeof(struct iovec);
        ret = socket_validate_user_struct(user_shadow->msg_iov, iov_bytes);
        if (ret < 0)
            return ret;

        struct iovec *kernel_iov = malloc(iov_bytes);
        if (!kernel_iov)
            return -ENOMEM;
        if (copy_from_user(kernel_iov, user_shadow->msg_iov, iov_bytes)) {
            free(kernel_iov);
            return -EFAULT;
        }

        for (size_t i = 0; i < user_shadow->msg_iovlen; i++) {
            if (!kernel_iov[i].len)
                continue;

            ret = socket_validate_user_mapped_buffer(kernel_iov[i].iov_base,
                                                     kernel_iov[i].len);
            if (ret < 0) {
                free(kernel_iov);
                return ret;
            }
        }

        *kernel_iov_out = kernel_iov;
    }

    if (user_shadow->msg_namelen > 0) {
        ret = socket_validate_user_mapped_buffer(user_shadow->msg_name,
                                                 user_shadow->msg_namelen);
        if (ret < 0) {
            socket_release_iov_copy(*kernel_iov_out);
            *kernel_iov_out = NULL;
            return ret;
        }
    }

    if (user_shadow->msg_controllen > 0) {
        ret = socket_validate_user_mapped_buffer(user_shadow->msg_control,
                                                 user_shadow->msg_controllen);
        if (ret < 0) {
            socket_release_iov_copy(*kernel_iov_out);
            *kernel_iov_out = NULL;
            return ret;
        }
    }

    *kernel_msg = *user_shadow;
    kernel_msg->msg_iov = *kernel_iov_out;
    return 0;
}

static int socket_copy_msghdr_back_to_user(struct msghdr *user_msg,
                                           const struct msghdr *user_shadow,
                                           const struct msghdr *kernel_msg) {
    if (!user_msg || !user_shadow || !kernel_msg)
        return -EINVAL;

    struct msghdr out = *user_shadow;
    out.msg_namelen = kernel_msg->msg_namelen;
    out.msg_controllen = kernel_msg->msg_controllen;
    out.msg_flags = kernel_msg->msg_flags;

    return copy_to_user(user_msg, &out, sizeof(out)) ? -EFAULT : 0;
}

static int socket_copy_timeout_from_user(const struct timespec *user_timeout,
                                         uint64_t *timeout_ns_out) {
    if (!timeout_ns_out)
        return -EINVAL;

    if (!user_timeout) {
        *timeout_ns_out = UINT64_MAX;
        return 0;
    }

    int ret = socket_validate_user_struct(user_timeout, sizeof(*user_timeout));
    if (ret < 0)
        return ret;

    struct timespec timeout;
    if (copy_from_user(&timeout, user_timeout, sizeof(timeout)))
        return -EFAULT;

    if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 ||
        timeout.tv_nsec >= 1000000000L)
        return -EINVAL;

    uint64_t timeout_ns = (uint64_t)timeout.tv_nsec;
    if ((uint64_t)timeout.tv_sec > UINT64_MAX / 1000000000ULL)
        timeout_ns = UINT64_MAX;
    else {
        uint64_t sec_ns = (uint64_t)timeout.tv_sec * 1000000000ULL;
        if (sec_ns > UINT64_MAX - timeout_ns)
            timeout_ns = UINT64_MAX;
        else
            timeout_ns += sec_ns;
    }

    *timeout_ns_out = timeout_ns;
    return 0;
}

static uint64_t socket_timeout_deadline(uint64_t timeout_ns) {
    if (timeout_ns == UINT64_MAX)
        return UINT64_MAX;

    uint64_t now = nano_time();
    if (timeout_ns > UINT64_MAX - now)
        return UINT64_MAX;
    return now + timeout_ns;
}

static int64_t socket_deadline_remaining_ns(uint64_t deadline) {
    if (deadline == UINT64_MAX)
        return -1;

    uint64_t now = nano_time();
    if (now >= deadline)
        return 0;

    uint64_t remaining = deadline - now;
    if (remaining > (uint64_t)INT64_MAX)
        return INT64_MAX;
    return (int64_t)remaining;
}

static int socket_wait_fd_event(fd_t *fd, uint32_t events, int64_t timeout_ns,
                                const char *reason) {
    if (!fd || !fd->node)
        return -EBADF;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, events);
    if (vfs_poll_wait_arm(fd->node, &wait) < 0)
        return -EINVAL;

    int ret = vfs_poll_wait_sleep(fd->node, &wait, timeout_ns, reason);
    vfs_poll_wait_disarm(&wait);

    if (ret == EOK)
        return 0;
    if (ret == ETIMEDOUT)
        return -ETIMEDOUT;
    if (ret < 0)
        return ret;
    return -EINTR;
}

static int socket_store_mmsg_len(struct mmsghdr *msgvec, unsigned int idx,
                                 int64_t len) {
    unsigned int msg_len =
        len > (int64_t)UINT32_MAX ? UINT32_MAX : (unsigned int)len;
    return copy_to_user(&msgvec[idx].msg_len, &msg_len, sizeof(msg_len))
               ? -EFAULT
               : 0;
}

uint64_t sys_shutdown(uint64_t fd, uint64_t how) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    fd_t *node = current_task->fd_info->fds[fd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (!handle || !handle->op || !handle->op->shutdown)
        return -ENOSYS;

    return handle->op->shutdown(fd, how);
}

uint64_t sys_getpeername(int fd, struct sockaddr_un *addr, socklen_t *addrlen) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;
    if (!addrlen)
        return -EFAULT;

    socklen_t user_len = 0;
    if (copy_from_user(&user_len, addrlen, sizeof(socklen_t)))
        return (uint64_t)-EFAULT;
    fd_t *node = current_task->fd_info->fds[fd];
    if (!is_socket(node))
        return -ENOTSOCK;

    void *kaddr = calloc(1, DEFAULT_PAGE_SIZE);
    socklen_t kaddrlen = user_len;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->getpeername) {
        uint64_t ret = handle->op->getpeername(fd, kaddr, &kaddrlen);
        if ((int64_t)ret < 0) {
            free(kaddr);
            return ret;
        }

        size_t copy_len = MIN((size_t)user_len, (size_t)kaddrlen);
        if (copy_len && addr && copy_to_user(addr, kaddr, copy_len)) {
            free(kaddr);
            return (uint64_t)-EFAULT;
        }

        free(kaddr);

        if (copy_to_user(addrlen, &kaddrlen, sizeof(socklen_t)))
            return (uint64_t)-EFAULT;

        return ret;
    }

    free(kaddr);

    return -ENOSYS;
}

uint64_t sys_getsockname(int sockfd, struct sockaddr_un *addr,
                         socklen_t *addrlen) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM ||
        !current_task->fd_info->fds[sockfd])
        return -EBADF;
    if (!addrlen)
        return -EFAULT;

    socklen_t user_len = 0;
    if (copy_from_user(&user_len, addrlen, sizeof(socklen_t)))
        return (uint64_t)-EFAULT;
    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!is_socket(node))
        return -ENOTSOCK;

    void *kaddr = calloc(1, DEFAULT_PAGE_SIZE);
    socklen_t kaddrlen = user_len;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->getsockname) {
        uint64_t ret = handle->op->getsockname(sockfd, kaddr, &kaddrlen);
        if ((int64_t)ret < 0) {
            free(kaddr);
            return ret;
        }

        size_t copy_len = MIN((size_t)user_len, (size_t)kaddrlen);
        if (copy_len && addr && copy_to_user(addr, kaddr, copy_len)) {
            free(kaddr);
            return (uint64_t)-EFAULT;
        }

        free(kaddr);

        if (copy_to_user(addrlen, &kaddrlen, sizeof(socklen_t)))
            return (uint64_t)-EFAULT;

        return ret;
    }

    free(kaddr);

    return -ENOSYS;
}

uint64_t sys_setsockopt(int fd, int level, int optname, const void *optval,
                        socklen_t optlen) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[fd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->setsockopt) {
        void *koptval = NULL;
        int ret = socket_alloc_copy_from_user(optval, optlen, &koptval);
        if (ret < 0)
            return ret;

        uint64_t out =
            handle->op->setsockopt(fd, level, optname, koptval, optlen);
        free(koptval);
        return out;
    }
    return -ENOSYS;
}

uint64_t sys_getsockopt(int fd, int level, int optname, void *optval,
                        socklen_t *optlen) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;
    if (!optlen)
        return -EFAULT;
    fd_t *node = current_task->fd_info->fds[fd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->getsockopt) {
        socklen_t user_len = 0;
        if (copy_from_user(&user_len, optlen, sizeof(user_len)))
            return -EFAULT;
        if (user_len && !optval)
            return -EFAULT;

        void *koptval = NULL;
        if (user_len) {
            koptval = calloc(1, user_len);
            if (!koptval)
                return -ENOMEM;
        }

        socklen_t koptlen = user_len;
        uint64_t ret =
            handle->op->getsockopt(fd, level, optname, koptval, &koptlen);
        if ((int64_t)ret < 0) {
            free(koptval);
            return ret;
        }

        size_t copy_len = MIN((size_t)user_len, (size_t)koptlen);
        if (copy_len && copy_to_user(optval, koptval, copy_len)) {
            free(koptval);
            return -EFAULT;
        }
        free(koptval);

        if (copy_to_user(optlen, &koptlen, sizeof(koptlen)))
            return -EFAULT;
        return ret;
    }
    return -ENOSYS;
}

uint64_t sys_socket(int domain, int type, int protocol) {
    int fd = -EAFNOSUPPORT;
    for (int i = 0; i < socket_num; i++) {
        if (real_sockets[i]->domain == domain) {
            fd = real_sockets[i]->socket(domain, type, protocol);
            break;
        }
    }

    return fd;
}

uint64_t sys_socketpair(int domain, int type, int protocol, int *sv) {
    if (!sv || check_user_overflow((uint64_t)sv, sizeof(int) * 2)) {
        return -EFAULT;
    }

    int ksv[2] = {-1, -1};
    int fd = -EAFNOSUPPORT;
    for (int i = 0; i < socket_num; i++) {
        if (real_sockets[i]->domain == domain) {
            fd = real_sockets[i]->socketpair(domain, type, protocol, ksv);
            break;
        }
    }

    if (fd < 0) {
        return fd;
    }

    if (copy_to_user(sv, ksv, sizeof(ksv))) {
        if (ksv[0] >= 0)
            sys_close((uint64_t)ksv[0]);
        if (ksv[1] >= 0)
            sys_close((uint64_t)ksv[1]);
        return -EFAULT;
    }

    return fd;
}

uint64_t sys_bind(int sockfd, const struct sockaddr_un *addr,
                  socklen_t addrlen) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM ||
        !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->bind) {
        struct sockaddr_un *kaddr = NULL;
        int ret = socket_copy_sockaddr_from_user(addr, addrlen, &kaddr);
        if (ret < 0)
            return ret;
        uint64_t out = handle->op->bind(sockfd, kaddr, addrlen);
        free(kaddr);
        return out;
    }
    return 0;
}

uint64_t sys_listen(int sockfd, int backlog) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM ||
        !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->listen)
        return handle->op->listen(sockfd, backlog);
    return 0;
}

uint64_t sys_accept(int sockfd, struct sockaddr_un *addr, socklen_t *addrlen,
                    uint64_t flags) {
    if (!current_task || sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;

    fd_t *node = NULL;
    with_fd_info_lock(current_task->fd_info, {
        if (current_task->fd_info->fds[sockfd]) {
            node = vfs_dup(current_task->fd_info->fds[sockfd]);
        }
    });
    if (!node)
        return -EBADF;
    if (!is_socket(node)) {
        fd_release(node);
        return -ENOTSOCK;
    }

    socket_handle_t *handle = node->node->handle;
    uint64_t ret = 0;
    if (handle && handle->op && handle->op->accept) {
        struct sockaddr_un *kaddr = NULL;
        socklen_t kaddrlen = 0;
        socklen_t *kaddrlenp = NULL;

        if (addr) {
            if (!addrlen) {
                fd_release(node);
                return -EFAULT;
            }
            if (copy_from_user(&kaddrlen, addrlen, sizeof(kaddrlen))) {
                fd_release(node);
                return -EFAULT;
            }
            if (kaddrlen) {
                kaddr = calloc(1, kaddrlen);
                if (!kaddr) {
                    fd_release(node);
                    return -ENOMEM;
                }
            }
            kaddrlenp = &kaddrlen;
        }

        ret = handle->op->accept(sockfd, kaddr, kaddrlenp, flags);
        if ((int64_t)ret >= 0 && kaddrlenp) {
            size_t copy_len = MIN((size_t)kaddrlen, (size_t)*kaddrlenp);
            if (copy_len && copy_to_user(addr, kaddr, copy_len))
                ret = -EFAULT;
            if ((int64_t)ret >= 0 &&
                copy_to_user(addrlen, kaddrlenp, sizeof(*kaddrlenp)))
                ret = -EFAULT;
        }

        free(kaddr);
    }

    fd_release(node);
    return ret;
}

uint64_t sys_connect(int sockfd, const struct sockaddr_un *addr,
                     socklen_t addrlen) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM ||
        !current_task->fd_info->fds[sockfd])
        return -EBADF;
    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->connect) {
        struct sockaddr_un *kaddr = NULL;
        int ret = socket_copy_sockaddr_from_user(addr, addrlen, &kaddr);
        if (ret < 0)
            return ret;
        uint64_t out = handle->op->connect(sockfd, kaddr, addrlen);
        free(kaddr);
        return out;
    }
    return 0;
}

int64_t sys_send(int sockfd, void *buff, size_t len, int flags,
                 struct sockaddr_un *dest_addr, socklen_t addrlen) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;
    if (len > 0 && (!buff || check_user_overflow((uint64_t)buff, len) ||
                    check_unmapped((uint64_t)buff, len)))
        return -EFAULT;

    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!node)
        return -EBADF;
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->sendto) {
        struct sockaddr_un *kaddr = NULL;
        if (dest_addr && addrlen) {
            int ret =
                socket_copy_sockaddr_from_user(dest_addr, addrlen, &kaddr);
            if (ret < 0) {
                return ret;
            }
        }

        int64_t out =
            handle->op->sendto(sockfd, buff, len, flags, kaddr, addrlen);
        free(kaddr);
        return out;
    }
    return 0;
}

int64_t sys_recv(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr_un *dest_addr, socklen_t *addrlen) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;
    if (len > 0 && (!buf || check_user_overflow((uint64_t)buf, len) ||
                    check_unmapped((uint64_t)buf, len)))
        return -EFAULT;

    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!node)
        return -EBADF;
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->recvfrom) {
        struct sockaddr_un *kaddr = NULL;
        socklen_t user_addrlen = 0;
        socklen_t *kaddrlenp = NULL;

        if (dest_addr) {
            if (!addrlen) {
                return -EFAULT;
            }
            if (copy_from_user(&user_addrlen, addrlen, sizeof(user_addrlen))) {
                return -EFAULT;
            }
            if (user_addrlen) {
                kaddr = calloc(1, user_addrlen);
                if (!kaddr) {
                    return -ENOMEM;
                }
            }
            kaddrlenp = &user_addrlen;
        }

        int64_t ret =
            handle->op->recvfrom(sockfd, buf, len, flags, kaddr, kaddrlenp);
        if (ret >= 0 && kaddrlenp) {
            size_t copy_len = MIN((size_t)user_addrlen, (size_t)*kaddrlenp);
            if (copy_len && copy_to_user(dest_addr, kaddr, copy_len))
                ret = -EFAULT;
            if (ret >= 0 &&
                copy_to_user(addrlen, kaddrlenp, sizeof(*kaddrlenp)))
                ret = -EFAULT;
        }

        free(kaddr);
        return ret;
    }
    return 0;
}

int64_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;

    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!node)
        return -EBADF;
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->sendmsg) {
        struct msghdr kmsg;
        struct msghdr user_shadow;
        struct iovec *kiov = NULL;
        int ret = socket_copy_msghdr_from_user(msg, &kmsg, &user_shadow, &kiov);
        if (ret < 0)
            return ret;

        int64_t out = handle->op->sendmsg(sockfd, &kmsg, flags);
        socket_release_iov_copy(kiov);
        return out;
    }
    return 0;
}

int64_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    if (sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;

    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!node)
        return -EBADF;
    if (!is_socket(node))
        return -ENOTSOCK;

    socket_handle_t *handle = node->node->handle;
    if (handle && handle->op && handle->op->recvmsg) {
        struct msghdr kmsg;
        struct msghdr user_shadow;
        struct iovec *kiov = NULL;
        int ret = socket_copy_msghdr_from_user(msg, &kmsg, &user_shadow, &kiov);
        if (ret < 0)
            return ret;

        int64_t out = handle->op->recvmsg(sockfd, &kmsg, flags);
        int copy_back_ret = 0;
        if (out >= 0)
            copy_back_ret =
                socket_copy_msghdr_back_to_user(msg, &user_shadow, &kmsg);

        socket_release_iov_copy(kiov);
        if (copy_back_ret < 0)
            return copy_back_ret;
        return out;
    }
    return 0;
}

int64_t sys_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                     int flags) {
    int ret = socket_validate_mmsg_array(msgvec, vlen);
    if (ret < 0)
        return ret;

    unsigned int sent = 0;
    for (; sent < vlen; sent++) {
        int64_t out = sys_sendmsg(sockfd, &msgvec[sent].msg_hdr, flags);
        if (out < 0)
            return sent ? (int64_t)sent : out;

        ret = socket_store_mmsg_len(msgvec, sent, out);
        if (ret < 0)
            return ret;
    }

    return sent;
}

int64_t sys_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                     int flags, struct timespec *timeout) {
    int ret = socket_validate_mmsg_array(msgvec, vlen);
    if (ret < 0)
        return ret;

    uint64_t timeout_ns = UINT64_MAX;
    ret = socket_copy_timeout_from_user(timeout, &timeout_ns);
    if (ret < 0)
        return ret;

    if (sockfd < 0 || sockfd >= MAX_FD_NUM)
        return -EBADF;

    fd_t *node = current_task->fd_info->fds[sockfd];
    if (!node)
        return -EBADF;
    if (!is_socket(node))
        return -ENOTSOCK;

    uint64_t deadline = socket_timeout_deadline(timeout_ns);
    unsigned int received = 0;
    int recv_flags = flags;

    while (received < vlen) {
        bool should_wait = !(recv_flags & MSG_DONTWAIT);
        if (should_wait) {
            int64_t remaining_ns = socket_deadline_remaining_ns(deadline);
            if (remaining_ns == 0)
                break;

            ret = socket_wait_fd_event(node, EPOLLIN, remaining_ns, "recvmmsg");
            if (ret == -ETIMEDOUT)
                break;
            if (ret < 0)
                return received ? (int64_t)received : ret;
        }

        int call_flags = (recv_flags & ~MSG_WAITFORONE) | MSG_DONTWAIT;
        int64_t out =
            sys_recvmsg(sockfd, &msgvec[received].msg_hdr, call_flags);
        if (out == -(EWOULDBLOCK))
            out = -EAGAIN;
        if (out == -EAGAIN) {
            if (!should_wait)
                return received ? (int64_t)received : out;
            continue;
        }
        if (out < 0)
            return received ? (int64_t)received : out;

        ret = socket_store_mmsg_len(msgvec, received, out);
        if (ret < 0)
            return ret;

        received++;
        if ((flags & MSG_WAITFORONE) && received == 1)
            recv_flags |= MSG_DONTWAIT;
    }

    return received;
}
