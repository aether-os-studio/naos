#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

typedef struct fsfd_ctx {
    fs_t *fs;
} fsfd_ctx_t;

uint64_t sys_fsopen(const char *fsname, unsigned int flags) {
    for (int i = 1; i < fs_nextid; i++) {
        if (!strcmp(all_fs[i]->name, fsname)) {
            fsfd_ctx_t *ctx = malloc(sizeof(fsfd_ctx_t));
            ctx->fs = all_fs[i];

            int fd = -1;
            for (int i = 3; i < MAX_FD_NUM; i++) {
                if (!current_task->fd_info->fds[i]) {
                    fd = i;
                    break;
                }
            }

            vfs_node_t node = vfs_node_alloc(NULL, NULL);
            node->type = file_none;
            node->handle = ctx;
            node->refcount++;
            node->size = 0;
            current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
            current_task->fd_info->fds[fd]->node = node;
            current_task->fd_info->fds[fd]->flags = flags;

            return fd;
        }
    }

    return -ENOENT;
}

uint64_t sys_statfs(const char *path, struct statfs *buf) {
    vfs_node_t node = vfs_open(path);
    if (!node)
        return -ENOENT;

    if (node->parent == rootdir && !strcmp(node->name, "proc")) {
        for (int i = 1; i < fs_nextid; i++) {
            if (!strcmp(all_fs[i]->name, "proc")) {
                buf->f_type = all_fs[i]->magic;
            }
        }
    }

    return -ENOENT;
}

uint64_t sys_fstatfs(int fd, struct statfs *buf) {
    if (fd < 0 && fd > MAX_FD_NUM && !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    fsfd_ctx_t *ctx = node->handle;

    buf->f_type = ctx->fs->magic;

    return -ENOENT;
}

void fsfd_init() {
    // fsfd_fsid = vfs_regist(&fsfd);
}
