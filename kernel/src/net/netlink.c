#include <net/netlink.h>
#include <task/task.h>

extern vfs_node_t sockfs_root;
extern int sockfsfd_id;

static int netlink_socket_fsid = 0;

int netlink_bind(uint64_t fd, const struct sockaddr_un *addr, socklen_t addrlen)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *sock = handle->sock;
    memcpy(sock->bind_addr, addr, sizeof(struct sockaddr_nl));

    return 0;
}

size_t netlink_getsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t *optlen)
{
    return 0;
}

size_t netlink_setsockopt(uint64_t fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return 0;
}

size_t netlink_recv_uevent(struct msghdr *msg, int flags)
{
    return 0;
}

size_t netlink_recvmsg(uint64_t fd, struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *sock = handle->sock;

    struct sockaddr_nl *addr = msg->msg_name;
    if (msg->msg_namelen != sizeof(struct sockaddr_nl))
    {
        return (size_t)-EINVAL;
    }

    if (addr->nl_pid == 0)
    {
        // KERNEL SPACE
        switch (sock->protocol)
        {
        case NETLINK_KOBJECT_UEVENT:
            return netlink_recv_uevent(msg, flags);

        default:
            return (size_t)-EINVAL;
        }
    }
    else
    {
        // TODO
        return (size_t)-ENOSYS;
    }
}

size_t netlink_sendmsg(uint64_t fd, const struct msghdr *msg, int flags)
{
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    struct netlink_sock *sock = handle->sock;

    // TODO
    return 0;
}

socket_op_t netlink_ops = {
    .bind = netlink_bind,
    .getsockopt = netlink_getsockopt,
    .setsockopt = netlink_setsockopt,
    .sendmsg = netlink_sendmsg,
    .recvmsg = netlink_recvmsg,
};

int netlink_socket(int domain, int type, int protocol)
{
    if (current_task->uid != 0) // 需要root权限
        return -EPERM;

    char buf[128];
    sprintf(buf, "sock%d", sockfsfd_id++);

    struct netlink_sock *nl_sk = malloc(sizeof(struct netlink_sock));
    memset(nl_sk, 0, sizeof(struct netlink_sock));
    nl_sk->lock.lock = 0;
    nl_sk->protocol = protocol;
    nl_sk->bind_addr = malloc(sizeof(struct sockaddr_nl));
    memset(nl_sk->bind_addr, 0, sizeof(struct sockaddr_nl));

    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));

    vfs_node_t socknode = vfs_node_alloc(sockfs_root, buf);
    socknode->type = file_socket;
    socknode->fsid = netlink_socket_fsid;
    socknode->refcount++;
    socknode->handle = handle;

    handle->op = &netlink_ops;
    handle->sock = nl_sk;

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
        return -EBADF;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = socknode;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = 0;

    return i;
}

int netlink_socket_pair(int type, int protocol, int *sv)
{
    return 0;
}

static int dummy()
{
    return 0;
}

static struct vfs_callback netlink_callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
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
    .poll = (vfs_poll_t)dummy,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

void netlink_init()
{
    netlink_socket_fsid = vfs_regist("socketfs", &netlink_callback);
}
