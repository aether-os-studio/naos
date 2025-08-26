#include <net/socket/netsock.h>

socket_op_t netsock_ops = {
    .accept = netsock_accept,
    .listen = netsock_listen,
    .bind = netsock_bind,
    .connect = netsock_connect,
    .sendto = netsock_sendto,
    .recvfrom = netsock_recvfrom,
    .sendmsg = netsock_sendmsg,
    .recvmsg = netsock_recvmsg,
    .getpeername = netsock_getpeername,
    .getsockopt = netsock_getsockopt,
    .setsockopt = netsock_setsockopt,
};

size_t netsock_getpeername(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

int netsock_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

int netsock_listen(uint64_t fd, int backlog)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

int netsock_accept(uint64_t fd, struct sockaddr_un *addr, socklen_t *addrlen, uint64_t flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

extern int smoltcp_connect(int smoltcp_fd, const void *addr, uint32_t addrlen);

int netsock_connect(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return smoltcp_connect(netsock->handle_fd, (const void *)addr, addrlen);
}

extern int smoltcp_sendto(int smoltcp_fd, const void *in, size_t limit, int flags, void *addr, uint32_t len);

size_t netsock_sendto(uint64_t fd, uint8_t *in, size_t limit, int flags, struct sockaddr_un *addr, uint32_t len)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return smoltcp_sendto(netsock->handle_fd, (const void *)in, limit, flags, (void *)addr, len);
}

extern int smoltcp_recvfrom(int smoltcp_fd, const void *in, size_t limit, int flags, void *addr, uint32_t *len);

size_t netsock_recvfrom(uint64_t fd, uint8_t *out, size_t limit, int flags, struct sockaddr_un *addr, uint32_t *len)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return smoltcp_recvfrom(netsock->handle_fd, (void *)out, limit, flags, (void *)addr, len);
}

size_t netsock_recvmsg(uint64_t fd, struct msghdr *msg, int flags)
{
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));

        size_t singleCnt = netsock_recvfrom(
            fd, curr->iov_base, curr->len,
            noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0)
            return singleCnt;

        cnt += singleCnt;
    }

    return cnt;
}

size_t netsock_sendmsg(uint64_t fd, const struct msghdr *msg, int flags)
{
    size_t cnt = 0;
    bool noblock = flags & MSG_DONTWAIT;

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        struct iovec *curr = (struct iovec *)((size_t)msg->msg_iov + i * sizeof(struct iovec));

        size_t singleCnt = netsock_sendto(
            fd, curr->iov_base, curr->len,
            noblock ? MSG_DONTWAIT : 0, NULL, 0);

        if ((int64_t)singleCnt < 0)
            return singleCnt;

        cnt += singleCnt;
    }

    return cnt;
}

size_t netsock_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

size_t netsock_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    netsock_t *netsock = handle->sock;

    return 0;
}

extern int smoltcp_socket(int domain, int type, int protocol);

bool netsock_close(void *current)
{
    return true;
}

extern int smoltcp_poll(int smoltcp_fd, uint32_t events);

int netsock_poll(void *file, size_t events)
{
    socket_handle_t *handle = file;
    netsock_t *netsock = handle->sock;

    return smoltcp_poll(netsock->handle_fd, events);
}

static int dummy()
{
    return 0;
}

static int netsock_fsid = 0;

static struct vfs_callback netsock_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)netsock_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)netsock_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)vfs_generic_dup,
};

void netsock_init()
{
    netsock_fsid = vfs_regist("netsock", &netsock_callback);
}

int netsock_socket(int domain, int type, int protocol)
{
    int smoltcp_fd = smoltcp_socket(domain, type, protocol);
    if (smoltcp_fd < 0)
        return smoltcp_fd;

    vfs_node_t socknode = vfs_node_alloc(NULL, "netsock");
    socknode->type = file_socket;
    socknode->fsid = netsock_fsid;
    socknode->refcount++;
    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    netsock_t *netsock = malloc(sizeof(socket_t));
    memset(netsock, 0, sizeof(socket_t));

    handle->sock = netsock;
    handle->op = &netsock_ops;
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

    netsock->handle_fd = smoltcp_fd;

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = socknode;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = 0;

    handle->fd = current_task->fd_info->fds[i];

    return i;
}
