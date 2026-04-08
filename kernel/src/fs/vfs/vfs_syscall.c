#include "fs/vfs/vfs.h"
#include "task/task.h"

int vfs_sys_openat(int dfd, const char *pathname,
                   const struct vfs_open_how *how) {
    struct vfs_file *file = NULL;
    int ret;

    ret = vfs_openat(dfd, pathname, how, &file);
    if (ret < 0)
        return ret;

    ret = task_install_file(current_task, file,
                            (how && (how->flags & O_CLOEXEC)) ? FD_CLOEXEC : 0,
                            0);
    if (ret < 0) {
        vfs_file_put(file);
        return ret;
    }

    vfs_file_put(file);
    return ret;
}

int vfs_sys_close(int fd) {
    return task_close_file_descriptor(current_task, fd);
}

ssize_t vfs_sys_read(int fd, void *buf, size_t count) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_read_file(file, buf, count, NULL);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_pread64(int fd, void *buf, size_t count, loff_t pos) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_read_file(file, buf, count, &pos);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_write(int fd, const void *buf, size_t count) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_write_file(file, buf, count, NULL);
    vfs_file_put(file);
    return ret;
}

ssize_t vfs_sys_pwrite64(int fd, const void *buf, size_t count, loff_t pos) {
    struct vfs_file *file;
    ssize_t ret;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;
    ret = vfs_write_file(file, buf, count, &pos);
    vfs_file_put(file);
    return ret;
}
