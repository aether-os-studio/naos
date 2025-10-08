#include <fs/fs_syscall.h>
#include <boot/boot.h>
#include <net/socket.h>

uint64_t sys_mount(char *dev_name, char *dir_name, char *type, uint64_t flags,
                   void *data) {
    vfs_node_t dir = vfs_open((const char *)dir_name);
    if (!dir) {
        return (uint64_t)-ENOENT;
    }

    vfs_node_t dev = vfs_open((const char *)dev_name);

    if (vfs_mount(dev, dir, (const char *)type)) {
        return -ENOENT;
    }

    return 0;
}

uint64_t sys_umount2(const char *target, uint64_t flags) {
    vfs_unmount(target);
    return 0;
}

uint64_t sys_open(const char *name, uint64_t flags, uint64_t mode) {
    uint64_t i = 0;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        return (uint64_t)-EMFILE;
    }

    int create_mode = (flags & O_CREAT);

    vfs_node_t node = vfs_open(name);
    if (!node && !create_mode) {
        // serial_fprintk("Opening file %s failed\n", name);
        return (uint64_t)-ENOENT;
    }

    if (!node) {
        int ret = 0;
        if (mode & O_DIRECTORY) {
            ret = vfs_mkdir(name);
        } else {
            ret = vfs_mkfile(name);
        }
        if (ret < 0)
            return (uint64_t)-ENOSPC;

        node = vfs_open(name);
        if (!node)
            return (uint64_t)-ENOENT;
    }

    current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[i]->node = node;
    current_task->fd_info->fds[i]->offset = 0;
    current_task->fd_info->fds[i]->flags = flags;
    node->refcount++;

    return i;
}

uint64_t sys_openat(uint64_t dirfd, const char *name, uint64_t flags,
                    uint64_t mode) {
    if (!name || check_user_overflow((uint64_t)name, strlen(name))) {
        return (uint64_t)-EFAULT;
    }
    char *path = at_resolve_pathname(dirfd, (char *)name);
    if (!path)
        return (uint64_t)-ENOMEM;

    uint64_t ret = sys_open(path, flags, mode);

    free(path);

    return ret;
}

uint64_t sys_fsync(uint64_t fd) {
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    return 0;
}

uint64_t sys_close(uint64_t fd) {
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    current_task->fd_info->fds[fd]->offset = 0;
    if (current_task->fd_info->fds[fd]->node->lock.l_pid == current_task->pid) {
        current_task->fd_info->fds[fd]->node->lock.l_type = F_UNLCK;
        current_task->fd_info->fds[fd]->node->lock.l_pid = 0;
    }

    vfs_close(current_task->fd_info->fds[fd]->node);
    free(current_task->fd_info->fds[fd]);

    current_task->fd_info->fds[fd] = NULL;

    return 0;
}

uint64_t sys_close_range(uint64_t fd, uint64_t maxfd, uint64_t flags) {
    if (fd > maxfd) {
        return (uint64_t)-EINVAL;
    }

    if (maxfd > MAX_FD_NUM) {
        maxfd = MAX_FD_NUM;
    }

    for (uint64_t fd_ = fd; fd_ <= maxfd; fd_++) {
        if (current_task->fd_info->fds[fd_]) {
            sys_close(fd_);
        }
    }

    return 0;
}

uint64_t sys_copy_file_range(uint64_t fd_in, uint64_t *offset_in,
                             uint64_t fd_out, uint64_t *offset_out,
                             uint64_t len, uint64_t flags) {
    if (fd_in >= MAX_FD_NUM || fd_out >= MAX_FD_NUM) {
        return (uint64_t)-EBADF;
    }

    fd_t *in_fd = current_task->fd_info->fds[fd_in];
    fd_t *out_fd = current_task->fd_info->fds[fd_out];
    if (!in_fd || !out_fd) {
        return (uint64_t)-EBADF;
    }

    if (out_fd->offset >= out_fd->node->size && out_fd->node->size > 0)
        return 0;

    uint64_t src_offset = offset_in ? *offset_in : in_fd->offset;
    uint64_t dst_offset = offset_out ? *offset_out : out_fd->offset;

    uint64_t length = in_fd->node->size > len ? len : in_fd->node->size;
    uint8_t *buffer = (uint8_t *)alloc_frames_bytes(length);
    size_t copy_total = 0;

    ssize_t ret = vfs_read_fd(in_fd, buffer, src_offset, length);
    if (ret < 0) {
        free_frames_bytes(buffer, length);
        return (uint64_t)-EIO;
    }

    if ((copy_total = vfs_write_fd(out_fd, buffer, dst_offset, length)) ==
        (ssize_t)-1) {
        free_frames_bytes(buffer, length);
        return (uint64_t)-EIO;
    }
    vfs_update(out_fd->node);
    free_frames_bytes(buffer, length);
    out_fd->offset += copy_total;

    return copy_total;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len) {
    if (!buf || check_user_overflow((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    if (current_task->fd_info->fds[fd]->node->type & file_dir) {
        return (uint64_t)-EISDIR; // 读取目录时返回正确错误码
    }

    if (!buf) {
        return (uint64_t)-EFAULT;
    }

    ssize_t ret = vfs_read_fd(current_task->fd_info->fds[fd], buf,
                              current_task->fd_info->fds[fd]->offset, len);

    if (ret > 0) {
        current_task->fd_info->fds[fd]->offset += ret;
    }

    if (ret == -EAGAIN) {
        return (uint64_t)-EAGAIN; // 保持非阻塞I/O语义
    }

    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len) {
    if (!buf || check_user_overflow((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    if (current_task->fd_info->fds[fd]->node->type & file_dir) {
        return (uint64_t)-EISDIR; // 读取目录时返回正确错误码
    }

    if (!buf) {
        return (uint64_t)-EFAULT;
    }

    ssize_t ret = vfs_write_fd(current_task->fd_info->fds[fd], buf,
                               current_task->fd_info->fds[fd]->offset, len);

    if (ret > 0) {
        current_task->fd_info->fds[fd]->offset += ret;
    }

    if (ret == -EAGAIN) {
        return (uint64_t)-EAGAIN; // 保持非阻塞I/O语义
    }

    return ret;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence) {
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    int64_t real_offset = offset;
    if (real_offset < 0 &&
        current_task->fd_info->fds[fd]->node->type & file_none &&
        whence != SEEK_CUR)
        return (uint64_t)-EBADF;

    switch (whence & 3) {
    case SEEK_SET:
        current_task->fd_info->fds[fd]->offset = real_offset;
        break;
    case SEEK_CUR:
        current_task->fd_info->fds[fd]->offset += real_offset;
        if ((int64_t)current_task->fd_info->fds[fd]->offset < 0) {
            current_task->fd_info->fds[fd]->offset = 0;
        } else if (current_task->fd_info->fds[fd]->offset >
                   current_task->fd_info->fds[fd]->node->size) {
            current_task->fd_info->fds[fd]->offset =
                current_task->fd_info->fds[fd]->node->size;
        }

        break;
    case SEEK_END:
        current_task->fd_info->fds[fd]->offset =
            current_task->fd_info->fds[fd]->node->size - real_offset;
        break;

    default:
        return (uint64_t)-ENOSYS;
        break;
    }

    return current_task->fd_info->fds[fd]->offset;
}

uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg) {
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    return vfs_ioctl(current_task->fd_info->fds[fd]->node, cmd, arg);
}

uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count) {
    if (!iovec ||
        check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec))) {
        return (uint64_t)-EFAULT;
    }
    if ((uint64_t)iovec == 0) {
        return -EINVAL;
    }

    ssize_t total_read = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (iovec[i].len == 0)
            continue;

        ssize_t ret = sys_read(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0) {
            return (uint64_t)ret;
        }
        total_read += ret;
        if ((size_t)ret < iovec[i].len)
            break;
    }
    return total_read;
}

uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count) {
    if (!iovec ||
        check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec))) {
        return (uint64_t)-EFAULT;
    }
    if ((uint64_t)iovec == 0) {
        return -EINVAL;
    }

    ssize_t total_written = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (iovec[i].len == 0)
            continue;

        ssize_t ret = sys_write(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0) {
            return (uint64_t)ret;
        }
        total_written += ret;
        if ((size_t)ret < iovec[i].len)
            break;
    }
    return total_written;
}

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size) {
    if (check_user_overflow(buf, size)) {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (!current_task->fd_info->fds[fd])
        return (uint64_t)-EBADF;
    if (!(current_task->fd_info->fds[fd]->node->type & file_dir))
        return (uint64_t)-ENOTDIR;

    struct dirent *dents = (struct dirent *)buf;
    fd_t *filedescriptor = current_task->fd_info->fds[fd];
    vfs_node_t node = filedescriptor->node;

    uint64_t child_count = (uint64_t)list_length(node->child);

    int64_t max_dents_num = size / sizeof(struct dirent);

    int64_t read_count = 0;

    uint64_t offset = 0;
    list_foreach(node->child, i) {
        if (offset < filedescriptor->offset)
            goto next;
        if (filedescriptor->offset >= (child_count * sizeof(struct dirent)))
            break;
        if (read_count >= max_dents_num)
            break;
        vfs_node_t child_node = (vfs_node_t)i->data;
        dents[read_count].d_ino = child_node->inode;
        dents[read_count].d_off = filedescriptor->offset;
        dents[read_count].d_reclen = sizeof(struct dirent);
        if (child_node->type & file_symlink)
            dents[read_count].d_type = DT_LNK;
        else if (child_node->type & file_none)
            dents[read_count].d_type = DT_REG;
        else if (child_node->type & file_dir)
            dents[read_count].d_type = DT_DIR;
        else
            dents[read_count].d_type = DT_UNKNOWN;
        strncpy(dents[read_count].d_name, child_node->name, 256);
        filedescriptor->offset += sizeof(struct dirent);
        read_count++;
    next:
        offset += sizeof(struct dirent);
    }

    return read_count * sizeof(struct dirent);
}

uint64_t sys_chdir(const char *dirname) {
    if (!dirname || check_user_overflow((uint64_t)dirname, strlen(dirname))) {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t new_cwd = vfs_open(dirname);
    if (!new_cwd)
        return (uint64_t)-ENOENT;

    current_task->cwd = new_cwd;

    return 0;
}

uint64_t sys_getcwd(char *cwd, uint64_t size) {
    if (!cwd || check_user_overflow((uint64_t)cwd, size)) {
        return (uint64_t)-EFAULT;
    }
    char *str = vfs_get_fullpath(current_task->cwd);
    if (size < (uint64_t)strlen(str)) {
        return (uint64_t)-ERANGE;
    }
    strncpy(cwd, str, size);
    free(str);
    return (uint64_t)strlen(cwd);
}

extern int unix_socket_fsid;
extern int unix_accept_fsid;

uint64_t sys_dup2(uint64_t fd, uint64_t newfd) {
    if (!current_task->fd_info->fds[fd])
        return (uint64_t)-EBADF;

    fd_t *new = vfs_dup(current_task->fd_info->fds[fd]);
    if (!new)
        return (uint64_t)-ENOSPC;

    if (current_task->fd_info->fds[newfd]) {
        vfs_close(current_task->fd_info->fds[newfd]->node);
        free(current_task->fd_info->fds[newfd]);
    }

    current_task->fd_info->fds[newfd] = new;

    return newfd;
}

// Implement the sys_dup3 function
uint64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags) {
    uint64_t fd = sys_dup2(oldfd, newfd);
    current_task->fd_info->fds[fd]->flags = flags;

    return newfd;
}

uint64_t sys_dup(uint64_t fd) {
    fd_t *f = current_task->fd_info->fds[fd];
    if (!f)
        return (uint64_t)-EBADF;

    uint64_t i;
    for (i = 3; i < MAX_FD_NUM; i++) {
        if (current_task->fd_info->fds[i] == NULL) {
            break;
        }
    }

    if (i == MAX_FD_NUM) {
        return (uint64_t)-EMFILE;
    }

    return sys_dup2(fd, i);
}

spinlock_t fcntl_lock = {0};

#define RWF_WRITE_LIFE_NOT_SET 0
#define RWH_WRITE_LIFE_NONE 1
#define RWH_WRITE_LIFE_SHORT 2
#define RWH_WRITE_LIFE_MEDIUM 3
#define RWH_WRITE_LIFE_LONG 4
#define RWH_WRITE_LIFE_EXTREME 5

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg) {
    if (fd > MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return (uint64_t)-EBADF;

    spin_lock(&fcntl_lock);

    switch (command) {
    case F_GETFD:
        spin_unlock(&fcntl_lock);
        return !!(current_task->fd_info->fds[fd]->flags & O_CLOEXEC);
    case F_SETFD:
        current_task->fd_info->fds[fd]->flags =
            (arg & 1) // FD_CLOEXEC
                ? (current_task->fd_info->fds[fd]->flags | O_CLOEXEC)
                : (current_task->fd_info->fds[fd]->flags & (~O_CLOEXEC));
        spin_unlock(&fcntl_lock);
        return 0;
    case F_DUPFD_CLOEXEC:
        uint64_t newfd = sys_dup(fd);
        current_task->fd_info->fds[newfd]->flags |= O_CLOEXEC;
        spin_unlock(&fcntl_lock);
        return newfd;
    case F_DUPFD:
        spin_unlock(&fcntl_lock);
        return sys_dup(fd);
    case F_GETFL:
        spin_unlock(&fcntl_lock);
        return current_task->fd_info->fds[fd]->flags;
    case F_SETFL:
        uint32_t valid_flags = O_APPEND | O_DIRECT | O_NOATIME | O_NONBLOCK;
        current_task->fd_info->fds[fd]->flags &= ~valid_flags;
        current_task->fd_info->fds[fd]->flags |= arg & valid_flags;
        spin_unlock(&fcntl_lock);
        return 0;
    case F_SETLKW:
    case F_SETLK: {
        struct flock lock;
        if (check_user_overflow(arg, sizeof(struct flock))) {
            spin_unlock(&fcntl_lock);
            return -EFAULT;
        }
        memcpy(&lock, (void *)arg, sizeof(struct flock));

        vfs_node_t node = current_task->fd_info->fds[fd]->node;
        struct flock *file_lock = &node->lock;

        if (lock.l_type != F_RDLCK && lock.l_type != F_WRLCK &&
            lock.l_type != F_UNLCK) {
            spin_unlock(&fcntl_lock);
            return -EINVAL;
        }

        if (lock.l_type == F_UNLCK) {
            if (file_lock->l_pid != current_task->pid) {
                spin_unlock(&fcntl_lock);
                return -EACCES;
            }
            file_lock->l_type = F_UNLCK;
            file_lock->l_pid = 0;
            spin_unlock(&fcntl_lock);
            return 0;
        }

        for (;;) {
            if (file_lock->l_type == F_UNLCK ||
                (file_lock->l_pid == current_task->pid &&
                 !(lock.l_type == F_WRLCK && file_lock->l_type == F_RDLCK))) {
                file_lock->l_type = lock.l_type;
                file_lock->l_pid = current_task->pid;
                spin_unlock(&fcntl_lock);
                return 0;
            }

            if (command == F_SETLK) {
                spin_unlock(&fcntl_lock);
                return -EAGAIN;
            }

            spin_unlock(&fcntl_lock);

            arch_yield();

            spin_lock(&fcntl_lock);
        }
    }
    case F_GET_SEALS:
    case F_ADD_SEALS:
        spin_unlock(&fcntl_lock);
        return 0;
    case F_GET_RW_HINT:
        spin_unlock(&fcntl_lock);
        if (!current_task->fd_info->fds[fd]->node->rw_hint) {
            return 0;
        }
        return current_task->fd_info->fds[fd]->node->rw_hint;

    case F_SET_RW_HINT:
        if (arg < RWH_WRITE_LIFE_NONE || arg > RWH_WRITE_LIFE_EXTREME) {
            spin_unlock(&fcntl_lock);
            return -EINVAL;
        }
        current_task->fd_info->fds[fd]->node->rw_hint = arg;
        spin_unlock(&fcntl_lock);
        return 0;
    default:
        spin_unlock(&fcntl_lock);
        return (uint64_t)-ENOSYS;
    }
}

uint64_t sys_stat(const char *fn, struct stat *buf) {
    vfs_node_t node = vfs_open(fn);
    if (!node) {
        // serial_fprintk("Stating file %s failed\n", fn);
        return (uint64_t)-ENOENT;
    }

    buf->st_dev = node->dev;
    buf->st_ino = node->inode;
    buf->st_nlink = 1;
    buf->st_mode =
        node->mode |
        (node->type & file_dir
             ? S_IFDIR
             : ((node->type & file_symlink)
                    ? S_IFLNK
                    : ((node->type & file_stream) ? S_IFCHR : S_IFREG)));
    buf->st_uid = current_task->uid;
    buf->st_gid = current_task->gid;
    buf->st_rdev = node->rdev;
    buf->st_blksize = node->blksz;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    return 0;
}

uint64_t sys_fstat(uint64_t fd, struct stat *buf) {
    if (!buf || check_user_overflow((uint64_t)buf, sizeof(struct stat))) {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM || current_task->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    buf->st_dev = node->dev;
    buf->st_ino = node->inode;
    buf->st_nlink = 1;
    buf->st_mode =
        node->mode |
        (node->type & file_dir
             ? S_IFDIR
             : ((node->type & file_symlink)
                    ? S_IFLNK
                    : ((node->type & file_stream) ? S_IFCHR : S_IFREG)));
    buf->st_uid = current_task->uid;
    buf->st_gid = current_task->gid;
    buf->st_rdev = node->rdev;
    buf->st_blksize = node->blksz;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

    return 0;
}

uint64_t sys_newfstatat(uint64_t dirfd, const char *pathname, struct stat *buf,
                        uint64_t flags) {
    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);

    if (!resolved) {
        return (uint64_t)-EINVAL;
    }

    uint64_t ret = sys_stat(resolved, buf);

    free(resolved);

    return ret;
}

uint64_t sys_statx(uint64_t dirfd, const char *pathname, uint64_t flags,
                   uint64_t mask, struct statx *buff) {
    if (!pathname ||
        check_user_overflow((uint64_t)pathname, strlen(pathname))) {
        return (uint64_t)-EFAULT;
    }
    if (!buff || check_user_overflow((uint64_t)buff, sizeof(struct statx))) {
        return (uint64_t)-EFAULT;
    }
    struct stat simple;
    memset(&simple, 0, sizeof(struct stat));
    uint64_t ret = sys_newfstatat(dirfd, pathname, &simple, flags);
    if ((int64_t)ret < 0)
        return ret;

    buff->stx_mask = mask;
    buff->stx_blksize = simple.st_blksize;
    buff->stx_attributes = 0;
    buff->stx_nlink = simple.st_nlink;
    buff->stx_uid = simple.st_uid;
    buff->stx_gid = simple.st_gid;
    buff->stx_mode = simple.st_mode;
    buff->stx_ino = simple.st_ino;
    buff->stx_size = simple.st_size;
    buff->stx_blocks = simple.st_blocks;
    buff->stx_attributes_mask = 0;

    buff->stx_atime.tv_sec = simple.st_atim.tv_sec;
    buff->stx_atime.tv_nsec = simple.st_atim.tv_nsec;

    buff->stx_btime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_btime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_ctime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_ctime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_mtime.tv_sec = simple.st_mtim.tv_sec;
    buff->stx_mtime.tv_nsec = simple.st_mtim.tv_nsec;

    // todo: special devices

    return 0;
}

size_t sys_access(char *filename, int mode) {
    (void)mode;
    struct stat buf;
    return sys_stat(filename, &buf);
}

uint64_t sys_faccessat(uint64_t dirfd, const char *pathname, uint64_t mode) {
    if (pathname[0] == '\0') { // by fd
        return 0;
    }
    if (check_user_overflow((uint64_t)pathname, strlen(pathname))) {
        return (uint64_t)-EFAULT;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname, uint64_t mode,
                        uint64_t flags) {
    if (pathname[0] == '\0') { // by fd
        return 0;
    }
    if (check_user_overflow((uint64_t)pathname, strlen(pathname))) {
        return (uint64_t)-EFAULT;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = sys_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_readlink(char *path, char *buf, uint64_t size) {
    if (path == NULL || buf == NULL || size == 0) {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)buf, size)) {
        return (uint64_t)-EFAULT;
    }

    vfs_node_t node = vfs_open(path);
    if (node == NULL) {
        return (uint64_t)-ENOENT;
    }

    if (!node->linkto) {
        // char *p = vfs_get_fullpath(node);
        // int str_len = strlen(p);
        // int node_name_len = strlen(node->name);
        // char *ptr = p + str_len - node_name_len;
        // char tmp[256];
        // sprintf(tmp, "%s", ptr);
        // uint64_t len = strnlen(tmp, size);
        // memcpy(buf, tmp, len);
        // buf[len] = 0;
        // free(p);
        // return len;
        return (uint64_t)-EINVAL;
    }

    ssize_t result = vfs_readlink(node, buf, (size_t)size);

    if (result < 0) {
        return (uint64_t)-EINVAL;
    }

    return result;
}

uint64_t sys_readlinkat(int dfd, char *path, char *buf, uint64_t size) {
    if (path == NULL || buf == NULL || size == 0) {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)path, strlen(path))) {
        return (uint64_t)-EFAULT;
    }
    if (check_user_overflow((uint64_t)buf, size)) {
        return (uint64_t)-EFAULT;
    }

    char *resolved = at_resolve_pathname(dfd, path);

    ssize_t res = sys_readlink(resolved, buf, (size_t)size);

    free(resolved);

    return res;
}

uint64_t sys_rmdir(const char *name) {
    if (check_user_overflow((uint64_t)name, strlen(name))) {
        return (uint64_t)-EFAULT;
    }
    vfs_node_t node = vfs_open(name);
    if (!node)
        return -ENOENT;
    if (!(node->type & file_dir))
        return -ENOTDIR;

    node->refcount++;

    uint64_t ret = vfs_delete(node);

    return ret;
}

uint64_t sys_unlink(const char *name) {
    vfs_node_t node = vfs_open(name);
    if (!node)
        return -ENOENT;

    uint64_t ret = vfs_delete(node);

    return ret;
}

uint64_t sys_unlinkat(uint64_t dirfd, const char *name, uint64_t flags) {
    if (check_user_overflow((uint64_t)name, strlen(name))) {
        return (uint64_t)-EFAULT;
    }
    char *path = at_resolve_pathname(dirfd, (char *)name);
    if (!path)
        return -ENOENT;

    uint64_t ret = sys_unlink((const char *)path);

    free(path);

    return ret;
}

uint64_t sys_rename(const char *old, const char *new) {
    vfs_node_t node = vfs_open(old);
    if (!node)
        return -ENOENT;
    int ret = vfs_rename(node, new);
    if (ret < 0)
        return ret;

    return 0;
}

uint64_t sys_renameat(uint64_t oldfd, const char *old, uint64_t newfd,
                      const char *new) {
    char *old_path = at_resolve_pathname_fullpath(oldfd, (char *)old);
    char *new_path = at_resolve_pathname_fullpath(newfd, (char *)new);

    vfs_node_t node = vfs_open(old_path);
    if (!node)
        return -ENOENT;
    int ret = vfs_rename(node, new_path);
    if (ret < 0) {
        free(old_path);
        free(new_path);
        return ret;
    }

    free(old_path);
    free(new_path);

    return 0;
}

uint64_t sys_fchdir(uint64_t fd) {
    if (fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;
    if (!(node->type & file_dir))
        return -ENOTDIR;

    current_task->cwd = node;

    return 0;
}

uint64_t sys_mkdir(const char *name, uint64_t mode) {
    int ret = vfs_mkdir(name);
    if (ret < 0) {
        return (uint64_t)ret;
    }
    vfs_chmod(name, mode);

    return 0;
}

uint64_t sys_mkdirat(int dfd, const char *name, uint64_t mode) {
    char *path = at_resolve_pathname(dfd, name);

    uint64_t ret = sys_mkdir((const char *)path, mode);

    free(path);

    return ret;
}

uint64_t sys_link(const char *name, const char *new) {
    if (check_user_overflow((uint64_t)name, strlen(name))) {
        return (uint64_t)-EFAULT;
    }
    int ret = vfs_link(name, new);

    return ret;
}

uint64_t sys_symlink(const char *name, const char *new) {
    if (check_user_overflow((uint64_t)name, strlen(name))) {
        return (uint64_t)-EFAULT;
    }
    int ret = vfs_symlink(new, name);

    return ret;
}

uint64_t sys_symlinkat(const char *name, int dfd, const char *new) {
    if (check_user_overflow((uint64_t)name, strlen(name)) ||
        check_user_overflow((uint64_t)new, strlen(new))) {
        return (uint64_t)-EFAULT;
    }

    char *buf = at_resolve_pathname_fullpath(dfd, new);

    int ret = vfs_symlink(name, buf);

    free(buf);

    return ret;
}

uint64_t sys_mknod(const char *name, uint16_t umode, int dev) {
    int ret = vfs_mknod(name, umode, dev);
    if (ret < 0)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_chmod(const char *name, uint16_t mode) {
    return vfs_chmod(name, mode);
}

uint64_t sys_fchmod(int fd, uint16_t mode) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    char *fullpath = vfs_get_fullpath(node);
    int ret = vfs_chmod(fullpath, mode);
    free(fullpath);
    return ret;
}

uint64_t sys_fchmodat(int dfd, const char *name, uint16_t mode) {
    char *resolved = at_resolve_pathname(dfd, name);
    int ret = vfs_chmod(name, mode);
    free(resolved);
    return ret;
}

uint64_t sys_chown(const char *filename, uint64_t uid, uint64_t gid) {
    int ret = vfs_chown(filename, uid, gid);
    return ret;
}

uint64_t sys_fchown(int fd, uint64_t uid, uint64_t gid) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    char *fullpath = vfs_get_fullpath(node);
    int ret = vfs_chown(fullpath, uid, gid);
    free(fullpath);
    return ret;
}

uint64_t sys_fchownat(int dfd, const char *name, uint64_t uid, uint64_t gid,
                      int flags) {
    char *resolved = at_resolve_pathname(dfd, name);
    vfs_chown((const char *)resolved, uid, gid);
    free(resolved);
    return 0;
}

uint64_t sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;

    vfs_resize(node, offset + len);

    return 0;
}

uint64_t sys_truncate(const char *path, uint64_t length) {
    vfs_node_t node = vfs_open(path);
    if (!node) {
        return (uint64_t)-ENOENT;
    }

    vfs_resize(node, length);

    return 0;
}

uint64_t sys_ftruncate(int fd, uint64_t length) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_resize(current_task->fd_info->fds[fd]->node, length);

    return 0;
}

uint64_t sys_flock(int fd, uint64_t operation) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t node = current_task->fd_info->fds[fd]->node;
    struct flock *lock = &node->lock;
    uint64_t pid = current_task->pid;

    // 提前检查参数有效性
    switch (operation & ~LOCK_NB) {
    case LOCK_SH:
    case LOCK_EX:
    case LOCK_UN:
        break;
    default:
        return -EINVAL;
    }

    // 非阻塞模式下立即检查冲突
    if (operation & LOCK_NB) {
        if ((operation & LOCK_SH) && lock->l_type == F_WRLCK)
            return -EWOULDBLOCK;
        if ((operation & LOCK_EX) && lock->l_type != F_UNLCK)
            return -EWOULDBLOCK;
    }

    // 实际加锁逻辑
    switch (operation & ~LOCK_NB) {
    case LOCK_SH:
    case LOCK_EX:
        while (lock->l_type != F_UNLCK && lock->l_pid != pid) {
            if (operation & LOCK_NB)
                return -EWOULDBLOCK;

            while (lock->lock) {
                arch_enable_interrupt();

                arch_pause();
            }

            arch_disable_interrupt();
        }
        lock->l_type = (operation & LOCK_EX) ? F_WRLCK : F_RDLCK;
        lock->l_pid = pid;
        break;

    case LOCK_UN:
        if (lock->l_pid != pid)
            return -EACCES;
        lock->l_type = F_UNLCK;
        lock->l_pid = 0;
        lock->lock = 1;
        break;
    }

    return 0;
}

uint64_t sys_fadvise64(int fd, uint64_t offset, uint64_t len, int advice) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    (void)offset;
    (void)len;
    (void)advice;

    return 0;
}

uint64_t sys_utimensat(int dfd, const char *pathname, struct timespec *ntimes,
                       int flags) {
    return 0;
}

uint64_t sys_futimesat(int dfd, const char *pathname, struct timeval *utimes) {
    return 0;
}

uint64_t sys_sysinfo(struct sysinfo *info) {
    if (check_user_overflow((uint64_t)info, sizeof(struct sysinfo)))
        return -EFAULT;

    memset(info, 0, sizeof(struct sysinfo));
    info->uptime = boot_get_boottime();
    info->loads[0] = 0;
    info->loads[1] = 0;
    info->loads[2] = 0;
    info->totalram = 0;
    info->freeram = 0;
    int proc_count = 0;
    for (int i = 0; i < MAX_TASK_NUM; i++) {
        if (!tasks[i]) {
            proc_count++;
        }
    }
    info->procs = proc_count;

    return 0;
}
