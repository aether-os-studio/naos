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

static void real_socket_v6_free_handle(vfs_node_t node) {
    socket_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;
    free(handle->sock);
    free(handle);
    node->handle = NULL;
}

bool real_socket_v6_close(vfs_node_t node) {
    real_socket_v6_free_handle(node);
    return true;
}

static vfs_operations_t real_socket_v6_vfs_ops = {
    .close = real_socket_v6_close,
    .free_handle = real_socket_v6_free_handle,
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
    for (i = 0; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        return -EMFILE;
    }

    with_fd_info_lock(current_task->fd_info, {
        current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
        memset(current_task->fd_info->fds[i], 0, sizeof(fd_t));
        current_task->fd_info->fds[i]->node = socknode;
        current_task->fd_info->fds[i]->offset = 0;
        current_task->fd_info->fds[i]->flags = 0;
    });

    handle->fd = current_task->fd_info->fds[i];

    return i;
}

fs_t socketv6 = {
    .name = "socketv6",
    .magic = 0,
    .ops = &real_socket_v6_vfs_ops,
    .flags = FS_FLAGS_HIDDEN,
};

void real_socket_v6_init() {
    realsockv6_fsid = vfs_regist(&socketv6);

    regist_socket(10, NULL, real_socket_v6_socket);
}
