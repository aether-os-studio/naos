#include <lwip/sockets.h>
#include <libs/aether/fs.h>
#include <libs/aether/task.h>
#include <libs/aether/net.h>

#include <lwip/netif.h>
#include <lwip/api.h>
#include <lwip/dhcp.h>
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <lwip/tcpip.h>

static int realsockv6_fsid = 0;

typedef struct real_socket_v6 {
} real_socket_v6_t;

int real_socket_v6_connect(uint64_t fd, const struct sockaddr_un *addr,
                           socklen_t addrlen) {
    socket_handle_t *handle = current_task->fd_info->fds[fd]->node->handle;
    real_socket_v6_t *sock = handle->sock;

    return -ENETUNREACH;
}

int real_socket_v6_bind(uint64_t fd, const struct sockaddr_un *addr,
                        socklen_t addrlen) {
    return -EADDRNOTAVAIL;
}

int real_socket_v6_listen(uint64_t fd, int backlog) { return -EADDRINUSE; }

socket_op_t real_socket_v6_ops = {
    .connect = real_socket_v6_connect,
    .bind = real_socket_v6_bind,
    .listen = real_socket_v6_listen,
};

bool real_socket_v6_close(void *current) { return true; }

static int dummy() { return 0; }

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)real_socket_v6_close,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
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
    .poll = (vfs_poll_t)dummy,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)vfs_generic_dup,

    .free_handle = vfs_generic_free_handle,
};

int real_socket_v6_socket(int domain, int type, int protocol) {
    vfs_node_t socknode = vfs_node_alloc(NULL, "realsockv6");
    socknode->type = file_socket;
    socknode->fsid = realsockv6_fsid;
    socknode->refcount++;
    socket_handle_t *handle = malloc(sizeof(socket_handle_t));
    memset(handle, 0, sizeof(socket_handle_t));
    real_socket_v6_t *real_socket_v6 = malloc(sizeof(real_socket_v6_t));
    memset(real_socket_v6, 0, sizeof(real_socket_v6_t));

    handle->sock = real_socket_v6;
    handle->op = &real_socket_v6_ops;
    socknode->handle = handle;

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

    handle->fd = current_task->fd_info->fds[i];

    return i;
}

fs_t socketv6 = {
    .name = "socketv6",
    .magic = 0,
    .callback = &callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void real_socket_v6_init() {
    realsockv6_fsid = vfs_regist(&socketv6);

    regist_socket(10, real_socket_v6_socket);
}
