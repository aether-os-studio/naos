#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

uint64_t sys_fsopen(const char *fsname, unsigned int flags) { return -ENOENT; }

uint64_t sys_statfs(const char *path, struct statfs *buf) {
    vfs_node_t node = vfs_open(path);
    if (!node)
        return -ENOENT;

    if (node->fsid > (sizeof(all_fs) / sizeof(all_fs[0])))
        return -EINVAL;

    fs_t *fs = all_fs[node->fsid];
    if (!fs)
        return -ENOENT;

    buf->f_type = fs->magic;

    return 0;
}

uint64_t sys_fstatfs(int fd, struct statfs *buf) {
    if (fd < 0 && fd > MAX_FD_NUM && !current_task->fd_info->fds[fd])
        return -EBADF;

    return -ENOENT;
}

void fsfd_init() {}
