#include <init/abis.h>
#include <init/callbacks.h>
#include <fs/fs_syscall.h>
#include <boot/boot.h>
#include <net/socket.h>
#include <drivers/kernel_logger.h>
#include <mm/cache.h>
#include <fs/vfs/notify.h>
#include <task/task_syscall.h>

#define FIONBIO_INTERNAL_DISABLE ((ssize_t) - 1)
#define FIONBIO_INTERNAL_ENABLE ((ssize_t) - 2)

static uint64_t do_unlink(const char *name);
static volatile uint64_t tmpfile_seq = 1;

static uint64_t fd_open_file_flags(uint64_t open_flags) {
    return (open_flags & O_ACCMODE_FLAGS) | (open_flags & O_STATUS_FLAGS);
}

static bool file_lock_ranges_overlap(uint64_t start1, uint64_t end1,
                                     uint64_t start2, uint64_t end2) {
    if (end1 != UINT64_MAX && end1 <= start2)
        return false;
    if (end2 != UINT64_MAX && end2 <= start1)
        return false;
    return true;
}

static bool file_lock_ranges_touch_or_overlap(uint64_t start1, uint64_t end1,
                                              uint64_t start2, uint64_t end2) {
    if (file_lock_ranges_overlap(start1, end1, start2, end2))
        return true;
    if (end1 != UINT64_MAX && end1 == start2)
        return true;
    return end2 != UINT64_MAX && end2 == start1;
}

static int lseek_add_offset(int64_t base, int64_t delta, uint64_t *result_out) {
    if (!result_out)
        return -EINVAL;

    if ((delta > 0 && base > INT64_MAX - delta) ||
        (delta < 0 && base < INT64_MIN - delta)) {
        return -EOVERFLOW;
    }

    int64_t result = base + delta;
    if (result < 0)
        return -EINVAL;

    *result_out = (uint64_t)result;
    return 0;
}

static int file_lock_normalize(fd_t *fd, const flock_t *lock,
                               uint64_t *start_out, uint64_t *end_out) {
    if (!fd || !fd->f_inode || !lock || !start_out || !end_out)
        return -EINVAL;
    if (lock->l_len < 0)
        return -EINVAL;

    int64_t base = 0;
    switch (lock->l_whence) {
    case SEEK_SET:
        base = 0;
        break;
    case SEEK_CUR:
        base = (int64_t)fd_get_offset(fd);
        break;
    case SEEK_END:
        base = (int64_t)fd->f_inode->i_size;
        break;
    default:
        return -EINVAL;
    }

    if ((lock->l_start > 0 && base > INT64_MAX - lock->l_start) ||
        (lock->l_start < 0 && base < INT64_MIN - lock->l_start)) {
        return -EINVAL;
    }

    int64_t start_signed = base + lock->l_start;
    if (start_signed < 0)
        return -EINVAL;

    uint64_t start = (uint64_t)start_signed;
    uint64_t end = UINT64_MAX;
    if (lock->l_len > 0) {
        if ((uint64_t)lock->l_len > UINT64_MAX - start)
            return -EINVAL;
        end = start + (uint64_t)lock->l_len;
        if (end <= start)
            return -EINVAL;
    }

    *start_out = start;
    *end_out = end;
    return 0;
}

static vfs_file_lock_t *file_lock_find_conflict(vfs_node_t *node,
                                                uint64_t start, uint64_t end,
                                                int16_t type, int32_t pid) {
    if (!node)
        return NULL;

    vfs_file_lock_t *lock = NULL, *tmp = NULL;
    llist_for_each(lock, tmp, &node->file_locks, node) {
        if (lock->pid == pid)
            continue;
        if (!file_lock_ranges_overlap(lock->start, lock->end, start, end))
            continue;
        if (lock->type == F_WRLCK || type == F_WRLCK)
            return lock;
    }

    return NULL;
}

static int file_lock_unlock_pid_range(vfs_node_t *node, int32_t pid,
                                      uint64_t start, uint64_t end) {
    if (!node)
        return -EINVAL;

    vfs_file_lock_t *lock = NULL, *tmp = NULL;
    llist_for_each(lock, tmp, &node->file_locks, node) {
        if (lock->pid != pid)
            continue;
        if (!file_lock_ranges_overlap(lock->start, lock->end, start, end))
            continue;

        if (start <= lock->start && (end == UINT64_MAX || end >= lock->end)) {
            llist_delete(&lock->node);
            free(lock);
            continue;
        }

        if (start <= lock->start) {
            lock->start = end;
            continue;
        }

        if (end == UINT64_MAX || end >= lock->end) {
            lock->end = start;
            continue;
        }

        vfs_file_lock_t *split = calloc(1, sizeof(vfs_file_lock_t));
        if (!split)
            return -ENOMEM;
        llist_init_head(&split->node);
        split->start = end;
        split->end = lock->end;
        split->pid = lock->pid;
        split->type = lock->type;
        lock->end = start;
        llist_append(&node->file_locks, &split->node);
    }

    return 0;
}

static void file_lock_release_pid(vfs_node_t *node, int32_t pid) {
    if (!node)
        return;

    spin_lock(&node->file_locks_lock);
    (void)file_lock_unlock_pid_range(node, pid, 0, UINT64_MAX);
    spin_unlock(&node->file_locks_lock);
}

static int file_lock_getlk(fd_t *fd, flock_t *lock) {
    if (lock->l_type != F_RDLCK && lock->l_type != F_WRLCK)
        return -EINVAL;

    uint64_t start = 0, end = 0;
    int ret = file_lock_normalize(fd, lock, &start, &end);
    if (ret < 0)
        return ret;

    vfs_node_t *node = fd->f_inode;
    spin_lock(&node->file_locks_lock);
    vfs_file_lock_t *conflict = file_lock_find_conflict(
        node, start, end, lock->l_type, current_task->pid);
    if (!conflict) {
        lock->l_type = F_UNLCK;
        lock->l_pid = 0;
        spin_unlock(&node->file_locks_lock);
        return 0;
    }

    lock->l_type = conflict->type;
    lock->l_whence = SEEK_SET;
    lock->l_start = (int64_t)conflict->start;
    lock->l_len = conflict->end == UINT64_MAX
                      ? 0
                      : (int64_t)(conflict->end - conflict->start);
    lock->l_pid = conflict->pid;
    spin_unlock(&node->file_locks_lock);
    return 0;
}

static int file_lock_setlk(fd_t *fd, const flock_t *req, bool wait) {
    uint64_t start = 0, end = 0;
    int ret = file_lock_normalize(fd, req, &start, &end);
    if (ret < 0)
        return ret;

    vfs_node_t *node = fd->f_inode;
    int32_t pid = current_task->pid;

    for (;;) {
        spin_lock(&node->file_locks_lock);

        if (req->l_type == F_UNLCK) {
            ret = file_lock_unlock_pid_range(node, pid, start, end);
            spin_unlock(&node->file_locks_lock);
            return ret;
        }

        vfs_file_lock_t *conflict =
            file_lock_find_conflict(node, start, end, req->l_type, pid);
        if (!conflict) {
            ret = file_lock_unlock_pid_range(node, pid, start, end);
            if (ret < 0) {
                spin_unlock(&node->file_locks_lock);
                return ret;
            }

            uint64_t merged_start = start;
            uint64_t merged_end = end;
            vfs_file_lock_t *lock = NULL, *tmp = NULL;
            llist_for_each(lock, tmp, &node->file_locks, node) {
                if (lock->pid != pid || lock->type != req->l_type)
                    continue;
                if (!file_lock_ranges_touch_or_overlap(
                        lock->start, lock->end, merged_start, merged_end))
                    continue;
                if (lock->start < merged_start)
                    merged_start = lock->start;
                if (lock->end > merged_end)
                    merged_end = lock->end;
                llist_delete(&lock->node);
                free(lock);
            }

            vfs_file_lock_t *new_lock = calloc(1, sizeof(vfs_file_lock_t));
            if (!new_lock) {
                spin_unlock(&node->file_locks_lock);
                return -ENOMEM;
            }

            llist_init_head(&new_lock->node);
            new_lock->start = merged_start;
            new_lock->end = merged_end;
            new_lock->pid = pid;
            new_lock->type = req->l_type;
            llist_append(&node->file_locks, &new_lock->node);
            spin_unlock(&node->file_locks_lock);
            return 0;
        }

        spin_unlock(&node->file_locks_lock);
        if (!wait)
            return -EAGAIN;

        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
        arch_disable_interrupt();
    }
}

static int generic_get_fd_path(int fd, struct vfs_path *path) {
    struct vfs_file *file;

    if (!path)
        return -EINVAL;
    memset(path, 0, sizeof(*path));

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;

    path->mnt = file->f_path.mnt;
    path->dentry = file->f_path.dentry;
    vfs_path_get(path);
    vfs_file_put(file);
    return 0;
}

static void generic_fill_stat_from_kstat(struct stat *buf,
                                         const struct vfs_kstat *stat) {
    if (!buf || !stat)
        return;

    memset(buf, 0, sizeof(*buf));
    buf->st_dev = (long)stat->dev;
    buf->st_ino = (unsigned long)stat->ino;
    buf->st_nlink = (unsigned long)stat->nlink;
    buf->st_mode = (int)stat->mode;
    buf->st_uid = (int)stat->uid;
    buf->st_gid = (int)stat->gid;
    buf->st_rdev = (long)stat->rdev;
    buf->st_blksize = (long)stat->blksize;
    buf->st_size = (long long)stat->size;
    buf->st_blocks = (unsigned long)stat->blocks;
    buf->st_atim.tv_sec = stat->atime.sec;
    buf->st_atim.tv_nsec = (long)stat->atime.nsec;
    buf->st_mtim.tv_sec = stat->mtime.sec;
    buf->st_mtim.tv_nsec = (long)stat->mtime.nsec;
    buf->st_ctim.tv_sec = stat->ctime.sec;
    buf->st_ctim.tv_nsec = (long)stat->ctime.nsec;
}

static void generic_fill_statx_from_kstat(struct statx *buf,
                                          const struct vfs_kstat *stat,
                                          const struct vfs_path *path,
                                          uint64_t mask) {
    if (!buf || !stat)
        return;

    memset(buf, 0, sizeof(*buf));
    buf->stx_mask = (uint32_t)mask;
    buf->stx_blksize = stat->blksize;
    buf->stx_nlink = stat->nlink;
    buf->stx_uid = stat->uid;
    buf->stx_gid = stat->gid;
    buf->stx_mode = stat->mode;
    buf->stx_ino = stat->ino;
    buf->stx_size = stat->size;
    buf->stx_blocks = stat->blocks;
    buf->stx_attributes = 0;
    buf->stx_attributes_mask = 0;
    if (path && path->mnt && path->dentry &&
        path->mnt->mnt_root == path->dentry)
        buf->stx_attributes_mask |= STATX_ATTR_MOUNT_ROOT;
    buf->stx_dev_major = (uint32_t)((stat->dev >> 8) & 0xFF);
    buf->stx_dev_minor = (uint32_t)(stat->dev & 0xFF);
    buf->stx_rdev_major = (uint32_t)((stat->rdev >> 8) & 0xFF);
    buf->stx_rdev_minor = (uint32_t)(stat->rdev & 0xFF);
    buf->stx_mnt_id = stat->mnt_id;
    buf->stx_atime.tv_sec = stat->atime.sec;
    buf->stx_atime.tv_nsec = stat->atime.nsec;
    buf->stx_btime.tv_sec = stat->btime.sec;
    buf->stx_btime.tv_nsec = stat->btime.nsec;
    buf->stx_ctime.tv_sec = stat->ctime.sec;
    buf->stx_ctime.tv_nsec = stat->ctime.nsec;
    buf->stx_mtime.tv_sec = stat->mtime.sec;
    buf->stx_mtime.tv_nsec = stat->mtime.nsec;
}

static int generic_setattr_path(const struct vfs_path *path, bool set_mode,
                                umode_t mode, bool set_uid, uid32_t uid,
                                bool set_gid, gid32_t gid, bool set_size,
                                uint64_t size) {
    struct vfs_kstat stat;
    struct vfs_inode *inode;

    if (!path || !path->dentry || !path->dentry->d_inode)
        return -ENOENT;

    inode = path->dentry->d_inode;
    if (!inode->i_op || !inode->i_op->setattr)
        return -EOPNOTSUPP;

    vfs_fill_generic_kstat(path, &stat);
    if (set_mode)
        stat.mode = (stat.mode & S_IFMT) | (mode & 07777);
    if (set_uid)
        stat.uid = uid;
    if (set_gid)
        stat.gid = gid;
    if (set_size)
        stat.size = size;
    return inode->i_op->setattr(path->dentry, &stat);
}

static int generic_link_pathat(const struct vfs_path *old_path, int newdfd,
                               const char *newname) {
    struct vfs_path new_parent = {0};
    struct vfs_qstr last = {0};
    struct vfs_dentry *existing = NULL;
    struct vfs_dentry *new_dentry = NULL;
    struct vfs_inode *new_dir;
    int ret;

    if (!old_path || !old_path->dentry || !old_path->dentry->d_inode)
        return -ENOENT;

    ret = vfs_path_parent_lookup(newdfd, newname, LOOKUP_PARENT, &new_parent,
                                 &last, NULL);
    if (ret < 0)
        return ret;

    new_dir = new_parent.dentry ? new_parent.dentry->d_inode : NULL;
    if (!new_dir || !new_dir->i_op || !new_dir->i_op->link) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    existing = vfs_d_lookup(new_parent.dentry, &last);
    if (existing) {
        ret = -EEXIST;
        goto out;
    }

    new_dentry = vfs_d_alloc(new_parent.dentry->d_sb, new_parent.dentry, &last);
    if (!new_dentry) {
        ret = -ENOMEM;
        goto out;
    }

    ret = new_dir->i_op->link(old_path->dentry, new_dir, new_dentry);
    if (ret == 0 && !(new_dentry->d_flags & VFS_DENTRY_HASHED))
        vfs_d_add(new_parent.dentry, new_dentry);

out:
    if (existing)
        vfs_dput(existing);
    if (new_dentry)
        vfs_dput(new_dentry);
    vfs_path_put(&new_parent);
    vfs_qstr_destroy(&last);
    return ret;
}

uint64_t sys_mount(char *dev_name, char *dir_name, char *type_user,
                   uint64_t flags, void *data) {
    unsigned long mnt_flags = 0;
    char devname[128] = "none";
    char dirname[512] = {0};
    char type[128] = "tmpfs";

    if (type_user) {
        if (copy_from_user_str(type, type_user, sizeof(type)))
            return (uint64_t)-EFAULT;
    }
    if (dev_name) {
        if (copy_from_user_str(devname, dev_name, sizeof(devname)))
            return (uint64_t)-EFAULT;
    }
    if (copy_from_user_str(dirname, dir_name, sizeof(dirname)))
        return (uint64_t)-EFAULT;

    if (flags & MS_RDONLY)
        mnt_flags |= VFS_MNT_READONLY;
    if (flags & MS_NOSUID)
        mnt_flags |= VFS_MNT_NOSUID;
    if (flags & MS_NODEV)
        mnt_flags |= VFS_MNT_NODEV;
    if (flags & MS_NOEXEC)
        mnt_flags |= VFS_MNT_NOEXEC;
    if (flags & MS_NOSYMFOLLOW)
        mnt_flags |= VFS_MNT_NOSYMFOLLOW;

    if (flags & MS_MOVE) {
        if (!dev_name)
            return (uint64_t)-EINVAL;
        if (flags & ~MS_MOVE)
            return (uint64_t)-EOPNOTSUPP;
        return (uint64_t)vfs_do_move_mount(AT_FDCWD, devname, AT_FDCWD,
                                           dirname);
    }

    if (flags & (MS_BIND | MS_REMOUNT | MS_SHARED | MS_PRIVATE | MS_SLAVE |
                 MS_UNBINDABLE)) {
        return (uint64_t)-EOPNOTSUPP;
    }

    return (uint64_t)vfs_do_mount(AT_FDCWD, dirname, type, mnt_flags, devname,
                                  data);
}

uint64_t sys_umount2(const char *target, uint64_t flags) {
    char target_k[512];
    if (copy_from_user_str(target_k, target, sizeof(target_k)))
        return (uint64_t)-EFAULT;
    return (uint64_t)vfs_do_umount(AT_FDCWD, target_k, (int)flags);
}

uint64_t sys_umask(uint64_t mask) {
    task_t *self = current_task;
    uint16_t old = 0022;

    if (!self || !self->fs)
        return old;

    old = self->fs->umask & 0777;
    self->fs->umask = mask & 0777;
    return old;
}

uint64_t do_sys_open(const char *name, uint64_t flags, uint64_t mode) {
    struct vfs_open_how how = {
        .flags = flags,
        .mode = mode,
    };

    if ((flags & O_TMPFILE) == O_TMPFILE)
        return -EINVAL;
    return (uint64_t)vfs_sys_openat(AT_FDCWD, name, &how);
}

uint64_t sys_open(const char *path, uint64_t flags, uint64_t mode) {
    char name[512];
    if (copy_from_user_str(name, path, sizeof(name)))
        return (uint64_t)-EFAULT;

    return do_sys_open(name, flags, mode);
}

uint64_t sys_openat(uint64_t dirfd, const char *name, uint64_t flags,
                    uint64_t mode) {
    struct vfs_open_how how = {
        .flags = flags,
        .mode = mode,
    };
    char name_k[512];
    if (!name || copy_from_user_str(name_k, name, sizeof(name_k))) {
        return (uint64_t)-EFAULT;
    }
    return (uint64_t)vfs_sys_openat((int)dirfd, name_k, &how);
}

uint64_t sys_name_to_handle_at(int dfd, const char *name,
                               struct file_handle *handle, int *mnt_id,
                               int flag) {
    struct vfs_kstat stat;
    int ret;

    if (!name || !handle || check_user_overflow((uint64_t)name, 1) ||
        check_user_overflow((uint64_t)handle, sizeof(struct file_handle))) {
        return (uint64_t)-EFAULT;
    }

    const unsigned int required_size = sizeof(uint64_t);

    if (handle->handle_bytes < required_size) {
        handle->handle_bytes = required_size;
        return (uint64_t)-EOVERFLOW;
    }

    ret = vfs_statx(dfd, name,
                    (flag & AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0, 0,
                    &stat);
    if (ret < 0)
        return (uint64_t)ret;

    handle->handle_bytes = required_size;
    handle->handle_type = 1; // Generic file handle type

    if (check_user_overflow((uint64_t)handle->f_handle, required_size)) {
        return (uint64_t)-EFAULT;
    }

    if (copy_to_user(handle->f_handle, &stat.ino, sizeof(uint64_t))) {
        return (uint64_t)-EFAULT;
    }

    int mount_id = (int)stat.mnt_id;

    if (mnt_id) {
        if (check_user_overflow((uint64_t)mnt_id, sizeof(int))) {
            return (uint64_t)-EFAULT;
        }
        if (copy_to_user(mnt_id, &mount_id, sizeof(int))) {
            return (uint64_t)-EFAULT;
        }
    }

    return 0;
}

uint64_t sys_open_by_handle_at(int mountdirfd, struct file_handle *handle,
                               int flags) {
    (void)mountdirfd;
    (void)handle;
    (void)flags;
    return (uint64_t)-EOPNOTSUPP;
}

uint64_t sys_inotify_init() { return sys_inotify_init1(0); }

uint64_t sys_inotify_init1(uint64_t flags) {
    struct vfs_file *file = NULL;
    int ret;

    if (flags & ~(uint64_t)(IN_CLOEXEC | IN_NONBLOCK))
        return (uint64_t)-EINVAL;

    ret = notifyfs_create_handle_file(&file, (unsigned int)flags, NULL);
    if (ret < 0)
        return (uint64_t)ret;

    ret = task_install_file(current_task, file,
                            (flags & IN_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(file);
    return (uint64_t)ret;
}

uint64_t sys_inotify_add_watch(uint64_t notifyfd, const char *path,
                               uint64_t mask) {
    struct vfs_file *notify_file = NULL;
    notifyfs_handle_t *handle;
    struct vfs_path target = {0};
    unsigned int lookup_flags;
    uint64_t wd = 0;
    int ret;

    if (!path)
        return (uint64_t)-EINVAL;

    notify_file = task_get_file(current_task, (int)notifyfd);
    if (!notify_file)
        return (uint64_t)-EBADF;
    if (!notifyfs_is_file(notify_file)) {
        vfs_file_put(notify_file);
        return (uint64_t)-EINVAL;
    }

    handle = notifyfs_file_handle(notify_file);
    if (!handle) {
        vfs_file_put(notify_file);
        return (uint64_t)-EINVAL;
    }

    lookup_flags = (mask & IN_DONT_FOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW;
    ret = vfs_filename_lookup(AT_FDCWD, path, lookup_flags, &target);
    if (ret < 0) {
        vfs_file_put(notify_file);
        return (uint64_t)ret;
    }
    if (!target.dentry || !target.dentry->d_inode) {
        vfs_path_put(&target);
        vfs_file_put(notify_file);
        return (uint64_t)-ENOENT;
    }

    ret = notifyfs_handle_add_watch(handle, notify_file->f_inode,
                                    target.dentry->d_inode, mask, &wd);
    vfs_path_put(&target);
    vfs_file_put(notify_file);
    if (ret < 0)
        return (uint64_t)ret;
    return wd;
}

uint64_t sys_inotify_rm_watch(uint64_t watchfd, uint64_t wd) {
    struct vfs_file *notify_file = NULL;
    notifyfs_handle_t *handle;
    int ret;

    notify_file = task_get_file(current_task, (int)watchfd);
    if (!notify_file)
        return (uint64_t)-EBADF;
    if (!notifyfs_is_file(notify_file)) {
        vfs_file_put(notify_file);
        return (uint64_t)-EINVAL;
    }

    handle = notifyfs_file_handle(notify_file);
    if (!handle) {
        vfs_file_put(notify_file);
        return (uint64_t)-EINVAL;
    }

    ret = notifyfs_handle_remove_watch(handle, wd);
    vfs_file_put(notify_file);
    return (uint64_t)ret;
}

uint64_t sys_fsync(uint64_t fd) {
    struct vfs_file *file = task_get_file(current_task, (int)fd);
    int ret;

    if (!file)
        return (uint64_t)-EBADF;

    ret = vfs_fsync_file(file);
    vfs_file_put(file);
    return ret < 0 ? (uint64_t)ret : 0;
}

uint64_t sys_close(uint64_t fd) {
    task_t *self = current_task;

    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;

    fd_t *entry = NULL;
    uint64_t ret = (uint64_t)-EBADF;
    with_fd_info_lock(self->fd_info, {
        entry = self->fd_info->fds[fd];
        if (!entry)
            break;

        file_lock_release_pid(entry->f_inode, self->pid);
        if (entry->f_inode->flock_lock.l_pid == self->pid) {
            entry->f_inode->flock_lock.l_type = F_UNLCK;
            entry->f_inode->flock_lock.l_pid = 0;
        }

        self->fd_info->fds[fd] = NULL;
        self->fd_info->fd_flags[fd] = 0;
        ret = 0;
    });

    if (ret)
        return ret;

    on_close_file_call(self, fd, entry);

    vfs_close_file(entry);

    return 0;
}

static int close_range_unshare_fd_table(task_t *self) {
    if (!self || !self->fd_info) {
        return -EINVAL;
    }

    fd_info_t *old = self->fd_info;
    if (old->ref_count <= 1) {
        return 0;
    }

    fd_info_t *new_info = calloc(1, sizeof(fd_info_t));
    if (!new_info) {
        return -ENOMEM;
    }

    mutex_init(&new_info->fdt_lock);
    new_info->ref_count = 1;

    with_fd_info_lock(old, {
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            if (old->fds[i]) {
                new_info->fds[i] = vfs_file_get(old->fds[i]);
                new_info->fd_flags[i] = old->fd_flags[i];
            }
        }
        old->ref_count--;
    });

    self->fd_info = new_info;
    return 0;
}

uint64_t sys_close_range(uint64_t fd, uint64_t maxfd, uint64_t flags) {
    if (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)) {
        return (uint64_t)-EINVAL;
    }

    if (fd > maxfd) {
        return (uint64_t)-EINVAL;
    }

    task_t *self = current_task;

    if (flags & CLOSE_RANGE_UNSHARE) {
        int ret = close_range_unshare_fd_table(self);
        if (ret < 0) {
            return (uint64_t)ret;
        }
    }

    if (fd >= MAX_FD_NUM) {
        return 0;
    }

    if (maxfd >= MAX_FD_NUM) {
        maxfd = MAX_FD_NUM - 1;
    }

    if (flags & CLOSE_RANGE_CLOEXEC) {
        with_fd_info_lock(self->fd_info, {
            for (uint64_t fd_ = fd; fd_ <= maxfd; fd_++) {
                fd_t *entry = self->fd_info->fds[fd_];
                if (!entry)
                    continue;
                self->fd_info->fd_flags[fd_] |= FD_CLOEXEC;
            }
        });
        return 0;
    }

    fd_t *to_close[MAX_FD_NUM] = {0};

    with_fd_info_lock(self->fd_info, {
        for (uint64_t fd_ = fd; fd_ <= maxfd; fd_++) {
            fd_t *entry = self->fd_info->fds[fd_];
            if (!entry)
                continue;

            file_lock_release_pid(entry->f_inode, self->pid);
            if (entry->f_inode->flock_lock.l_pid == self->pid) {
                entry->f_inode->flock_lock.l_type = F_UNLCK;
                entry->f_inode->flock_lock.l_pid = 0;
            }

            self->fd_info->fds[fd_] = NULL;
            self->fd_info->fd_flags[fd_] = 0;
            to_close[fd_] = entry;
        }
    });

    for (uint64_t fd_ = fd; fd_ <= maxfd; fd_++) {
        fd_t *entry = to_close[fd_];
        if (!entry)
            continue;
        on_close_file_call(self, fd_, entry);
        vfs_close_file(entry);
    }

    return 0;
}

uint64_t sys_copy_file_range(uint64_t fd_in, int *offset_in_user,
                             uint64_t fd_out, int *offset_out_user,
                             uint64_t len, uint64_t flags) {
    loff_t src_pos;
    loff_t dst_pos;
    if (fd_in >= MAX_FD_NUM || fd_out >= MAX_FD_NUM) {
        return (uint64_t)-EBADF;
    }

    task_t *self = current_task;

    fd_t *in_fd = self->fd_info->fds[fd_in];
    fd_t *out_fd = self->fd_info->fds[fd_out];
    if (!in_fd || !out_fd) {
        return (uint64_t)-EBADF;
    }

    if (flags)
        return (uint64_t)-EINVAL;

    if (fd_get_offset(out_fd) >= (uint64_t)out_fd->f_inode->i_size &&
        out_fd->f_inode->i_size > 0) {
        return 0;
    }

    int offset_in = 0;
    int offset_out = 0;
    if (offset_in_user) {
        if (copy_from_user(&offset_in, offset_in_user, sizeof(int)))
            return (uint64_t)-EFAULT;
    }
    if (offset_out_user) {
        if (copy_from_user(&offset_out, offset_out_user, sizeof(int)))
            return (uint64_t)-EFAULT;
    }

    uint64_t src_offset =
        offset_in_user ? (uint64_t)offset_in : fd_get_offset(in_fd);
    uint64_t dst_offset =
        offset_out_user ? (uint64_t)offset_out : fd_get_offset(out_fd);
    if (fd_get_flags(out_fd) & O_APPEND)
        dst_offset = out_fd->f_inode->i_size;

    if (src_offset >= in_fd->f_inode->i_size)
        return 0;

    uint64_t length = MIN(len, in_fd->f_inode->i_size - src_offset);
    uint8_t *buffer = (uint8_t *)alloc_frames_bytes(length);
    size_t copy_total = 0;

    src_pos = (loff_t)src_offset;
    dst_pos = (loff_t)dst_offset;

    ssize_t ret = vfs_read_file(in_fd, buffer, length, &src_pos);
    if (ret < 0) {
        free_frames_bytes(buffer, length);
        return (uint64_t)ret;
    }

    ret = vfs_write_file(out_fd, buffer, (size_t)ret, &dst_pos);
    if (ret < 0) {
        free_frames_bytes(buffer, length);
        return (uint64_t)ret;
    }
    copy_total = (size_t)ret;
    free_frames_bytes(buffer, length);
    if (!offset_in_user && copy_total > 0)
        fd_add_offset(in_fd, (int64_t)copy_total);
    if (!offset_out_user && copy_total > 0)
        fd_add_offset(out_fd, (int64_t)copy_total);

    return copy_total;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len) {
    struct vfs_file *file;
    ssize_t ret;

    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }
    file = task_get_file(current_task, (int)fd);
    if (!file)
        return (uint64_t)-EBADF;
    if (S_ISDIR(file->f_inode->i_mode)) {
        vfs_file_put(file);
        return (uint64_t)-EISDIR;
    }
    ret = vfs_read_file(file, buf, len, NULL);
    vfs_file_put(file);
    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len) {
    struct vfs_file *file;
    ssize_t ret;

    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    file = task_get_file(current_task, (int)fd);
    if (!file)
        return (uint64_t)-EBADF;
    if (S_ISDIR(file->f_inode->i_mode)) {
        vfs_file_put(file);
        return (uint64_t)-EISDIR;
    }
    ret = vfs_write_file(file, buf, len, NULL);
    vfs_file_put(file);
    return ret;
}

uint64_t sys_pread64(int fd, void *buf, size_t len, uint64_t offset) {
    struct vfs_file *file;
    loff_t pos = (loff_t)offset;
    ssize_t ret;

    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    file = task_get_file(current_task, fd);
    if (!file)
        return (uint64_t)-EBADF;
    if (S_ISDIR(file->f_inode->i_mode)) {
        vfs_file_put(file);
        return (uint64_t)-EISDIR;
    }
    ret = vfs_read_file(file, buf, len, &pos);
    vfs_file_put(file);
    return (uint64_t)ret;
}

uint64_t sys_pwrite64(int fd, const void *buf, size_t len, uint64_t offset) {
    struct vfs_file *file;
    loff_t pos = (loff_t)offset;
    ssize_t ret;

    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    file = task_get_file(current_task, fd);
    if (!file)
        return (uint64_t)-EBADF;
    if (S_ISDIR(file->f_inode->i_mode)) {
        vfs_file_put(file);
        return (uint64_t)-EISDIR;
    }
    ret = vfs_write_file(file, buf, len, &pos);
    vfs_file_put(file);
    return (uint64_t)ret;
}

uint64_t sys_sendfile(uint64_t out_fd, uint64_t in_fd, int *offset_ptr,
                      size_t count) {
    if (out_fd >= MAX_FD_NUM || in_fd >= MAX_FD_NUM)
        return -EBADF;

    task_t *self = current_task;

    fd_t *out_handle = self->fd_info->fds[out_fd];
    fd_t *in_handle = self->fd_info->fds[in_fd];
    loff_t read_pos = 0;
    if (out_handle == NULL || in_handle == NULL)
        return -EBADF;

    uint64_t current_offset = fd_get_offset(in_handle);
    size_t total_sent = 0;
    size_t remaining = count;

    if (offset_ptr != NULL) {
        int user_offset = 0;

        if (check_user_overflow((uint64_t)offset_ptr, sizeof(user_offset)) ||
            check_unmapped((uint64_t)offset_ptr, sizeof(user_offset))) {
            return -EFAULT;
        }
        if (copy_from_user(&user_offset, offset_ptr, sizeof(user_offset))) {
            return -EFAULT;
        }
        if (user_offset < 0) {
            return -EINVAL;
        }

        current_offset = (uint64_t)user_offset;
    }

    char *buffer = (char *)alloc_frames_bytes(PAGE_SIZE);
    if (buffer == NULL) {
        return -ENOMEM;
    }

    while (remaining > 0) {
        size_t bytes_to_read = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        ssize_t bytes_read = 0;
        ssize_t bytes_written = 0;
        read_pos = (loff_t)current_offset;
        bytes_read = vfs_read_file(in_handle, buffer, bytes_to_read, &read_pos);
        if (bytes_read <= 0) {
            if (bytes_read < 0 && total_sent == 0) {
                free_frames_bytes(buffer, PAGE_SIZE);
                return (uint64_t)bytes_read;
            }
            break;
        }
        bytes_written = vfs_write_file(out_handle, buffer, bytes_read, NULL);
        if (bytes_written <= 0) {
            if (total_sent == 0) {
                free_frames_bytes(buffer, PAGE_SIZE);
                return bytes_written < 0 ? (uint64_t)bytes_written : 0;
            }
            break;
        }
        if (bytes_written < bytes_read) {
            bytes_read = bytes_written;
        }
        current_offset += bytes_read;
        total_sent += bytes_read;
        remaining -= bytes_read;
    }
    free_frames_bytes(buffer, PAGE_SIZE);
    if (offset_ptr != NULL) {
        int out_offset =
            current_offset > (uint64_t)INT_MAX ? INT_MAX : (int)current_offset;
        if (copy_to_user(offset_ptr, &out_offset, sizeof(out_offset))) {
            return -EFAULT;
        }
    } else {
        fd_set_offset(in_handle, current_offset);
    }
    return total_sent;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence) {
    struct vfs_file *file;
    vfs_node_t *node;

    whence &= 0xffffffff;

    file = task_get_file(current_task, (int)fd);
    if (!file) {
        return (uint64_t)-EBADF;
    }

    node = file->f_inode;
    if (fd_get_flags(file) & O_PATH) {
        vfs_file_put(file);
        return (uint64_t)-EBADF;
    }
    if (node->type & (file_socket | file_fifo | file_stream)) {
        vfs_file_put(file);
        return (uint64_t)-ESPIPE;
    }

    if (whence == SEEK_DATA || whence == SEEK_HOLE) {
        uint64_t new_offset;
        if ((int64_t)offset < 0) {
            vfs_file_put(file);
            return (uint64_t)-EINVAL;
        }
        if (offset >= node->i_size) {
            vfs_file_put(file);
            return (uint64_t)-ENXIO;
        }
        new_offset = whence == SEEK_DATA ? offset : node->i_size;
        fd_set_offset(file, new_offset);
        vfs_file_put(file);
        return new_offset;
    }

    loff_t result = vfs_llseek_file(file, (loff_t)offset, (int)whence);
    vfs_file_put(file);
    return result < 0 ? (uint64_t)result : (uint64_t)result;
}

uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg) {
    task_t *self = current_task;
    fd_t *f;
    int ret = -ENOSYS;

    if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    f = self->fd_info->fds[fd];

    if (fd_get_flags(f) & O_PATH) {
        return (uint64_t)-EBADF;
    }

    switch (cmd) {
    case FIONBIO:
        if (!arg)
            return -EFAULT;
        int value = 0;
        if (copy_from_user(&value, (void *)arg, sizeof(value)))
            return -EFAULT;
        uint64_t file_flags = fd_get_flags(f);
        if (value)
            file_flags |= O_NONBLOCK;
        else
            file_flags &= ~O_NONBLOCK;
        fd_set_flags(f, file_flags);
        ret = 0;
        if (f->f_inode->type & file_socket) {
            ret = vfs_ioctl_file(f, cmd, arg);
            if (ret == -ENOTTY || ret == -ENOSYS)
                ret = 0;
        }
        break;
    case FIOCLEX:
        self->fd_info->fd_flags[fd] |= FD_CLOEXEC;
        ret = 0;
        break;
    case FIONCLEX:
        self->fd_info->fd_flags[fd] &= ~FD_CLOEXEC;
        ret = 0;
        break;

    default:
        ret = vfs_ioctl_file(f, cmd, arg);
        if ((cmd == TCGETS || cmd == TCSETS || cmd == TCGETS2 ||
             cmd == TIOCSCTTY || cmd == TIOCGWINSZ) &&
            ret < 0) {
            ret = -ENOTTY;
        }
        break;
    }
    if (ret == -ENOSYS) {
        printk("sys_ioctl: cmd %#010x not implemented, fs = %s\n", cmd,
               (f->f_inode && f->f_inode->i_sb && f->f_inode->i_sb->s_type)
                   ? f->f_inode->i_sb->s_type->name
                   : NULL);
    }

    return ret;
}

uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count) {
    if (count == 0) {
        return 0;
    }
    if (!iovec || count > SIZE_MAX / sizeof(struct iovec) ||
        check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec)) ||
        check_unmapped((uint64_t)iovec, count * sizeof(struct iovec))) {
        return (uint64_t)-EFAULT;
    }

    struct iovec *kiov = malloc(count * sizeof(struct iovec));
    if (!kiov) {
        return (uint64_t)-ENOMEM;
    }
    if (copy_from_user(kiov, iovec, count * sizeof(struct iovec))) {
        free(kiov);
        return (uint64_t)-EFAULT;
    }

    ssize_t total_read = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (kiov[i].iov_base == NULL || kiov[i].len == 0)
            continue;

        ssize_t ret = sys_read(fd, kiov[i].iov_base, kiov[i].len);
        if (ret < 0) {
            if (total_read > 0 &&
                (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR)) {
                free(kiov);
                return total_read;
            }
            free(kiov);
            return (uint64_t)ret;
        }
        total_read += ret;
        if ((size_t)ret < kiov[i].len)
            break;
    }
    free(kiov);
    return total_read;
}

uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count) {
    if (count == 0) {
        return 0;
    }
    if (!iovec || count > SIZE_MAX / sizeof(struct iovec) ||
        check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec)) ||
        check_unmapped((uint64_t)iovec, count * sizeof(struct iovec))) {
        return (uint64_t)-EFAULT;
    }

    struct iovec *kiov = malloc(count * sizeof(struct iovec));
    if (!kiov) {
        return (uint64_t)-ENOMEM;
    }
    if (copy_from_user(kiov, iovec, count * sizeof(struct iovec))) {
        free(kiov);
        return (uint64_t)-EFAULT;
    }

    ssize_t total_written = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (kiov[i].iov_base == NULL || kiov[i].len == 0)
            continue;

        ssize_t ret = sys_write(fd, kiov[i].iov_base, kiov[i].len);
        if (ret < 0) {
            if (total_written > 0 &&
                (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR)) {
                free(kiov);
                return total_written;
            }
            free(kiov);
            return (uint64_t)ret;
        }
        total_written += ret;
        if ((size_t)ret < kiov[i].len)
            break;
    }
    free(kiov);
    return total_written;
}

#define DIRENT_HEADER_SIZE offsetof(struct dirent, d_name)

static inline size_t dirent_reclen(size_t name_len) {
    return (DIRENT_HEADER_SIZE + name_len + 1 + 7) & ~7;
}

struct getdents_state {
    uint8_t *buf;
    uint64_t size;
    uint64_t written;
};

static int getdents_actor(struct vfs_dir_context *ctx, const char *name,
                          int namelen, loff_t next, ino64_t ino,
                          unsigned d_type) {
    struct getdents_state *state = (struct getdents_state *)ctx->private;
    struct dirent *dent;
    size_t reclen;

    if (!state || !name || namelen < 0)
        return -EINVAL;

    reclen = dirent_reclen((size_t)namelen);
    if (state->written + reclen > state->size)
        return -EINVAL;

    dent = (struct dirent *)(state->buf + state->written);
    memset(dent, 0, reclen);
    dent->d_ino = ino;
    dent->d_reclen = reclen;
    dent->d_off = next;
    dent->d_type = d_type;
    memcpy(dent->d_name, name, (size_t)namelen);
    dent->d_name[namelen] = '\0';
    state->written += reclen;
    return 0;
}

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size) {
    struct vfs_file *file;
    struct vfs_dir_context ctx = {0};
    struct getdents_state state = {0};
    int ret;

    if (check_user_overflow(buf, size) || check_unmapped(buf, size)) {
        return (uint64_t)-EFAULT;
    }

    file = task_get_file(current_task, (int)fd);
    if (!file)
        return (uint64_t)-EBADF;
    if (!S_ISDIR(file->f_inode->i_mode)) {
        vfs_file_put(file);
        return (uint64_t)-ENOTDIR;
    }

    state.buf = (uint8_t *)buf;
    state.size = size;
    ctx.pos = file->f_pos;
    ctx.actor = getdents_actor;
    ctx.private = &state;

    ret = vfs_iterate_dir(file, &ctx);
    vfs_file_put(file);
    if (ret < 0 && state.written == 0)
        return (uint64_t)ret;
    return state.written;
}

uint64_t sys_chdir(const char *dname) {
    char dirname[512];
    struct vfs_path path = {0};
    int ret;

    if (copy_from_user_str(dirname, dname, sizeof(dirname)))
        return (uint64_t)-EFAULT;

    ret = vfs_filename_lookup(AT_FDCWD, dirname, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    if (!path.dentry->d_inode || !S_ISDIR(path.dentry->d_inode->i_mode)) {
        vfs_path_put(&path);
        return (uint64_t)-ENOTDIR;
    }
    ret = task_fs_chdir(current_task, &path);
    vfs_path_put(&path);
    return ret;
}

uint64_t sys_chroot(const char *dname) {
    char dirname[512];
    struct vfs_path path = {0};
    int ret;

    if (copy_from_user_str(dirname, dname, sizeof(dirname)))
        return (uint64_t)-EFAULT;

    ret = vfs_filename_lookup(AT_FDCWD, dirname, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    if (!path.dentry->d_inode || !S_ISDIR(path.dentry->d_inode->i_mode)) {
        vfs_path_put(&path);
        return (uint64_t)-ENOTDIR;
    }

    ret = task_fs_chroot(current_task, &path);
    if (ret < 0) {
        vfs_path_put(&path);
        return (uint64_t)ret;
    }

    if (!vfs_path_is_ancestor(&path, task_fs_pwd_path(current_task))) {
        task_fs_chdir(current_task, &path);
    }

    vfs_path_put(&path);

    return 0;
}

uint64_t sys_getcwd(char *cwd, uint64_t size) {
    char *str = vfs_path_to_string(task_fs_pwd_path(current_task),
                                   task_fs_root_path(current_task));
    uint64_t to_copy;

    if (!str)
        return (uint64_t)-ENOMEM;
    to_copy = strlen(str) + 1;
    if (size < to_copy) {
        free(str);
        return (uint64_t)-ERANGE;
    }
    if (copy_to_user_str(cwd, str, size)) {
        free(str);
        return (uint64_t)-EFAULT;
    }
    free(str);
    return to_copy;
}

extern int unix_socket_fsid;
extern int unix_accept_fsid;

static uint64_t dup_to_exact(task_t *self, uint64_t fd, uint64_t newfd,
                             bool cloexec, bool allow_same_fd) {
    if (!self)
        return (uint64_t)-EBADF;
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (newfd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;

    uint64_t ret = newfd;
    bool replaced_existing = false;
    bool installed_new = false;
    fd_t *replaced_fd = NULL;
    unsigned int new_fd_flags = 0;
    with_fd_info_lock(self->fd_info, {
        if (!self->fd_info->fds[fd]) {
            ret = (uint64_t)-EBADF;
            break;
        }

        if (fd == newfd) {
            if (allow_same_fd) {
                ret = newfd;
            } else {
                ret = (uint64_t)-EINVAL;
            }
            break;
        }

        fd_t *newf = vfs_file_get(self->fd_info->fds[fd]);
        if (!newf) {
            ret = (uint64_t)-ENOSPC;
            break;
        }

        if (self->fd_info->fds[newfd]) {
            replaced_fd = self->fd_info->fds[newfd];
            self->fd_info->fds[newfd] = NULL;
            self->fd_info->fd_flags[newfd] = 0;
            replaced_existing = true;
        }

        new_fd_flags = cloexec ? FD_CLOEXEC : 0;
        self->fd_info->fds[newfd] = newf;
        self->fd_info->fd_flags[newfd] = new_fd_flags;
        installed_new = true;
    });

    if ((int64_t)ret >= 0 && installed_new) {
        if (replaced_existing) {
            on_close_file_call(self, newfd, replaced_fd);
            vfs_close_file(replaced_fd);
        }
        on_open_file_call(self, newfd);
    }

    return ret;
}

uint64_t sys_dup2(uint64_t fd, uint64_t newfd) {
    task_t *self = current_task;
    return dup_to_exact(self, fd, newfd, false, true);
}

static uint64_t dup_to_free_slot(task_t *self, uint64_t fd, uint64_t start,
                                 bool cloexec) {
    if (!self)
        return (uint64_t)-EBADF;
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    if (start >= MAX_FD_NUM)
        return (uint64_t)-EINVAL;

    uint64_t ret = (uint64_t)-EBADF;
    with_fd_info_lock(self->fd_info, {
        if (!self->fd_info->fds[fd]) {
            ret = (uint64_t)-EBADF;
            break;
        }

        uint64_t i;
        for (i = start; i < MAX_FD_NUM; i++) {
            if (!self->fd_info->fds[i])
                break;
        }

        if (i == MAX_FD_NUM) {
            ret = (uint64_t)-EMFILE;
            break;
        }

        fd_t *newf = vfs_file_get(self->fd_info->fds[fd]);
        if (!newf) {
            ret = (uint64_t)-ENOSPC;
            break;
        }

        self->fd_info->fds[i] = newf;
        self->fd_info->fd_flags[i] = cloexec ? FD_CLOEXEC : 0;
        on_open_file_call(self, i);
        ret = i;
    });

    return ret;
}

uint64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags) {
    if (flags & ~O_CLOEXEC)
        return (uint64_t)-EINVAL;
    task_t *self = current_task;
    return dup_to_exact(self, oldfd, newfd, !!(flags & O_CLOEXEC), false);
}

uint64_t sys_dup(uint64_t fd) {
    task_t *self = current_task;
    return dup_to_free_slot(self, fd, 0, false);
}

#define RWF_WRITE_LIFE_NOT_SET 0
#define RWH_WRITE_LIFE_NONE 1
#define RWH_WRITE_LIFE_SHORT 2
#define RWH_WRITE_LIFE_MEDIUM 3
#define RWH_WRITE_LIFE_LONG 4
#define RWH_WRITE_LIFE_EXTREME 5

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg) {
    task_t *self = current_task;
    fd_t *file;
    if (fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return (uint64_t)-EBADF;
    file = self->fd_info->fds[fd];

    switch (command) {
    case F_GETFD:
        return (self->fd_info->fd_flags[fd] & FD_CLOEXEC) ? FD_CLOEXEC : 0;
    case F_SETFD:
        self->fd_info->fd_flags[fd] =
            (self->fd_info->fd_flags[fd] & ~FD_CLOEXEC) |
            ((arg & FD_CLOEXEC) ? FD_CLOEXEC : 0);
        return 0;
    case F_DUPFD_CLOEXEC:
        return dup_to_free_slot(self, fd, arg, true);
    case F_DUPFD:
        return dup_to_free_slot(self, fd, arg, false);
    case F_GETFL:
        return fd_get_flags(file);
    case F_SETFL:
        if (fd_get_flags(file) & O_PATH)
            return (uint64_t)-EBADF;
        uint64_t file_flags = fd_get_flags(file);
        uint64_t valid_flags = O_SETFL_FLAGS;
        file_flags = (file_flags & ~valid_flags) | (arg & valid_flags);
        fd_set_flags(file, file_flags);
        int ret = 0;
        if (file->f_inode->type & file_socket) {
            int nonblock = !!(file_flags & O_NONBLOCK);
            ret = vfs_ioctl_file(file, FIONBIO,
                                 nonblock ? FIONBIO_INTERNAL_ENABLE
                                          : FIONBIO_INTERNAL_DISABLE);
            if (ret == -ENOTTY || ret == -ENOSYS)
                ret = 0;
        }
        return ret;
    case F_GETLK: {
        flock_t lock;
        if (check_user_overflow(arg, sizeof(lock))) {
            return -EFAULT;
        }
        memcpy(&lock, (void *)arg, sizeof(lock));
        int getlk_ret = file_lock_getlk(file, &lock);
        if (getlk_ret < 0)
            return getlk_ret;
        if (copy_to_user((void *)arg, &lock, sizeof(lock)))
            return -EFAULT;
        return 0;
    }
    case F_SETLKW:
    case F_SETLK: {
        flock_t lock;
        if (check_user_overflow(arg, sizeof(lock))) {
            return -EFAULT;
        }
        memcpy(&lock, (void *)arg, sizeof(lock));

        if (lock.l_type != F_RDLCK && lock.l_type != F_WRLCK &&
            lock.l_type != F_UNLCK) {
            return -EINVAL;
        }

        return file_lock_setlk(file, &lock, command == F_SETLKW);
    }
    case F_GETPIPE_SZ:
        return 512 * 1024;
    case F_SETPIPE_SZ:
        return 0;
    case F_GET_SEALS:
    case F_ADD_SEALS:
        return 0;
    case F_GET_RW_HINT:
        if (!file->f_inode->rw_hint) {
            return 0;
        }
        return file->f_inode->rw_hint;

    case F_SET_RW_HINT:
        if (arg < RWH_WRITE_LIFE_NONE || arg > RWH_WRITE_LIFE_EXTREME) {
            return -EINVAL;
        }
        file->f_inode->rw_hint = arg;
        return 0;
    default:
        printk("Unsupported fcntl command %#010lx\n", command);
        return (uint64_t)-EINVAL;
    }
}

uint64_t do_stat_path(const char *path, struct stat *buf) {
    struct vfs_kstat stat;
    int ret;

    ret = vfs_statx(AT_FDCWD, path, 0, 0, &stat);
    if (ret < 0)
        return (uint64_t)ret;

    generic_fill_stat_from_kstat(buf, &stat);
    return 0;
}

uint64_t sys_stat(const char *fn, struct stat *user_buf) {
    char path[512];
    if (copy_from_user_str(path, fn, sizeof(path)))
        return (uint64_t)-EFAULT;

    struct stat buf;
    uint64_t ret = do_stat_path(path, &buf);
    if ((int64_t)ret < 0)
        return ret;

    if (copy_to_user(user_buf, &buf, sizeof(struct stat)))
        return (uint64_t)-EFAULT;

    return 0;
}

uint64_t do_stat_fd(int fd, struct stat *buf) {
    struct vfs_path path = {0};
    struct vfs_kstat stat;
    int ret;

    ret = generic_get_fd_path(fd, &path);
    if (ret < 0)
        return ret;
    vfs_fill_generic_kstat(&path, &stat);
    generic_fill_stat_from_kstat(buf, &stat);
    vfs_path_put(&path);
    return 0;
}

uint64_t sys_fstat(uint64_t fd, struct stat *user_buf) {
    task_t *self = current_task;
    if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    struct stat res;
    int ret = do_stat_fd(fd, &res);
    if (ret < 0)
        return ret;

    if (copy_to_user(user_buf, &res, sizeof(struct stat)))
        return (uint64_t)-EFAULT;

    return 0;
}

uint64_t sys_newfstatat(uint64_t dirfd, const char *pathname_user,
                        struct stat *buf_user, uint64_t flags) {
    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    if ((flags & AT_EMPTY_PATH) && pathname[0] == '\0') {
        return sys_fstat(dirfd, buf_user);
    }

    struct stat buf;
    struct vfs_kstat stat;
    uint64_t ret = (uint64_t)vfs_statx(
        (int)dirfd, pathname,
        (flags & AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0, 0, &stat);
    if ((int64_t)ret < 0)
        return ret;
    generic_fill_stat_from_kstat(&buf, &stat);

    if (copy_to_user(buf_user, &buf, sizeof(struct stat)))
        return (uint64_t)-EFAULT;

    return 0;
}

uint64_t sys_statx(uint64_t dirfd, const char *pathname_user, uint64_t flags,
                   uint64_t mask, struct statx *buff_user) {
    struct vfs_path path = {0};
    struct vfs_kstat stat;
    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    struct statx res;
    struct statx *buff = &res;
    int ret;

    if ((flags & AT_EMPTY_PATH) && pathname[0] == '\0') {
        ret = generic_get_fd_path((int)dirfd, &path);
        if (ret < 0)
            return (uint64_t)ret;
        vfs_fill_generic_kstat(&path, &stat);
    } else {
        ret = vfs_filename_lookup(
            (int)dirfd, pathname,
            (flags & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW,
            &path);
        if (ret < 0)
            return (uint64_t)ret;
        if (path.dentry->d_inode && path.dentry->d_inode->i_op &&
            path.dentry->d_inode->i_op->getattr) {
            ret =
                path.dentry->d_inode->i_op->getattr(&path, &stat, mask, flags);
            if (ret < 0) {
                vfs_path_put(&path);
                return (uint64_t)ret;
            }
        } else {
            vfs_fill_generic_kstat(&path, &stat);
        }
    }

    generic_fill_statx_from_kstat(buff, &stat, &path, mask);
    if (copy_to_user(buff_user, buff, sizeof(struct statx))) {
        vfs_path_put(&path);
        return (uint64_t)-EFAULT;
    }
    vfs_path_put(&path);

    return 0;
}

size_t do_access(char *filename, int mode) {
    struct vfs_path path = {0};
    int ret;

    ret = vfs_filename_lookup(AT_FDCWD, filename, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return ret;
    if (path.dentry->d_inode && path.dentry->d_inode->i_op &&
        path.dentry->d_inode->i_op->permission) {
        ret =
            path.dentry->d_inode->i_op->permission(path.dentry->d_inode, mode);
        vfs_path_put(&path);
        return ret;
    }
    vfs_path_put(&path);
    return 0;
}

size_t sys_access(char *filename_user, int mode) {
    (void)mode;
    char filename[512];
    if (copy_from_user_str(filename, filename_user, sizeof(filename)))
        return (size_t)-EFAULT;

    return do_access(filename, mode);
}

uint64_t sys_faccessat(uint64_t dirfd, const char *pathname_user,
                       uint64_t mode) {
    struct vfs_path path = {0};
    int ret;

    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    if (pathname[0] == '\0') { // by fd
        return 0;
    }

    ret = vfs_filename_lookup((int)dirfd, pathname, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    if (path.dentry->d_inode && path.dentry->d_inode->i_op &&
        path.dentry->d_inode->i_op->permission) {
        ret = path.dentry->d_inode->i_op->permission(path.dentry->d_inode,
                                                     (int)mode);
    } else {
        ret = 0;
    }
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname_user,
                        uint64_t mode, uint64_t flags) {
    struct vfs_path path = {0};
    int ret;

    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    if ((flags & AT_EMPTY_PATH) && pathname[0] == '\0') { // by fd
        return 0;
    }

    ret = vfs_filename_lookup(
        (int)dirfd, pathname,
        (flags & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    if (path.dentry->d_inode && path.dentry->d_inode->i_op &&
        path.dentry->d_inode->i_op->permission) {
        ret = path.dentry->d_inode->i_op->permission(path.dentry->d_inode,
                                                     (int)mode);
    } else {
        ret = 0;
    }
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t do_readlink(char *path, char *buf, uint64_t size) {
    struct vfs_path vpath = {0};
    const char *target;
    size_t len;
    int ret;

    ret = vfs_filename_lookup(AT_FDCWD, path, LOOKUP_NOFOLLOW, &vpath);
    if (ret < 0)
        return (uint64_t)ret;
    if (!vpath.dentry->d_inode || !S_ISLNK(vpath.dentry->d_inode->i_mode) ||
        !vpath.dentry->d_inode->i_op ||
        !vpath.dentry->d_inode->i_op->get_link) {
        vfs_path_put(&vpath);
        return (uint64_t)-EINVAL;
    }

    target = vpath.dentry->d_inode->i_op->get_link(vpath.dentry,
                                                   vpath.dentry->d_inode, NULL);
    if (IS_ERR_OR_NULL(target)) {
        vfs_path_put(&vpath);
        return target ? (uint64_t)PTR_ERR(target) : (uint64_t)-ENOENT;
    }

    len = MIN((size_t)size, strlen(target));
    memcpy(buf, target, len);
    vfs_path_put(&vpath);
    return len;
}

uint64_t sys_readlink(char *path_user, char *buf_user, uint64_t size) {
    if (path_user == NULL || buf_user == NULL || size == 0) {
        return (uint64_t)-EFAULT;
    }

    char path[512];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    char *buf = malloc(size);
    if (!buf)
        return (uint64_t)-ENOMEM;
    memset(buf, 0, size);

    ssize_t result = do_readlink(path, buf, size);

    if (result < 0) {
        free(buf);
        return (uint64_t)result;
    }

    if (copy_to_user(buf_user, buf, result)) {
        free(buf);
        return (uint64_t)-EFAULT;
    }

    free(buf);

    return result;
}

uint64_t sys_readlinkat(int dfd, char *path_user, char *buf_user,
                        uint64_t size) {
    struct vfs_path vpath = {0};
    const char *target;
    size_t len;
    int ret;

    if (path_user == NULL || buf_user == NULL || size == 0) {
        return (uint64_t)-EFAULT;
    }

    char path[512];

    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    ret = vfs_filename_lookup(dfd, path, LOOKUP_NOFOLLOW, &vpath);
    if (ret < 0)
        return (uint64_t)ret;
    if (!vpath.dentry->d_inode || !S_ISLNK(vpath.dentry->d_inode->i_mode) ||
        !vpath.dentry->d_inode->i_op ||
        !vpath.dentry->d_inode->i_op->get_link) {
        vfs_path_put(&vpath);
        return (uint64_t)-EINVAL;
    }

    target = vpath.dentry->d_inode->i_op->get_link(vpath.dentry,
                                                   vpath.dentry->d_inode, NULL);
    if (IS_ERR_OR_NULL(target)) {
        vfs_path_put(&vpath);
        return target ? (uint64_t)PTR_ERR(target) : (uint64_t)-ENOENT;
    }
    len = MIN((size_t)size, strlen(target));
    ret = copy_to_user(buf_user, target, len);
    vfs_path_put(&vpath);
    return ret ? (uint64_t)-EFAULT : (uint64_t)len;
}

uint64_t sys_rmdir(const char *name_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name))) {
        return (uint64_t)-EFAULT;
    }
    return (uint64_t)vfs_unlinkat(AT_FDCWD, name, AT_REMOVEDIR);
}

static uint64_t do_unlink(const char *name) {
    return (uint64_t)vfs_unlinkat(AT_FDCWD, name, 0);
}

uint64_t sys_unlink(const char *name_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name))) {
        return (uint64_t)-EFAULT;
    }

    return do_unlink(name);
}

uint64_t sys_unlinkat(uint64_t dirfd, const char *name_user, uint64_t flags) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name))) {
        return (uint64_t)-EFAULT;
    }
    return (uint64_t)vfs_unlinkat((int)dirfd, name, (int)flags);
}

uint64_t do_rename(const char *old, const char *new) {
    return (uint64_t)vfs_renameat2(AT_FDCWD, old, AT_FDCWD, new, 0);
}

uint64_t sys_rename(const char *old_user, const char *new_user) {
    char old[512];
    char new[512];

    if (copy_from_user_str(old, old_user, sizeof(old)))
        return (uint64_t)-EFAULT;
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;

    return do_rename(old, new);
}

uint64_t sys_renameat(uint64_t oldfd, const char *old_user, uint64_t newfd,
                      const char *new_user) {
    char old[512];
    char new[512];

    if (copy_from_user_str(old, old_user, sizeof(old)))
        return (uint64_t)-EFAULT;
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;

    return (uint64_t)vfs_renameat2((int)oldfd, old, (int)newfd, new, 0);
}

uint64_t sys_renameat2(uint64_t oldfd, const char *old_user, uint64_t newfd,
                       const char *new_user, uint64_t flags) {
    char old[512];
    char new[512];

    if (copy_from_user_str(old, old_user, sizeof(old)))
        return (uint64_t)-EFAULT;
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;

    return (uint64_t)vfs_renameat2((int)oldfd, old, (int)newfd, new,
                                   (unsigned int)flags);
}

uint64_t sys_fchdir(uint64_t fd) {
    struct vfs_path path = {0};
    int ret = generic_get_fd_path((int)fd, &path);
    if (ret < 0)
        return ret;
    if (!path.dentry->d_inode || !S_ISDIR(path.dentry->d_inode->i_mode)) {
        vfs_path_put(&path);
        return -ENOTDIR;
    }
    ret = task_fs_chdir(current_task, &path);
    vfs_path_put(&path);
    return ret;
}

uint64_t do_mkdir(const char *name, uint64_t mode) {
    umode_t dir_mode = (umode_t)(mode & 0777);
    if (current_task && current_task->fs)
        dir_mode &= ~current_task->fs->umask;
    return (uint64_t)vfs_mkdirat(AT_FDCWD, name, dir_mode);
}

uint64_t sys_mkdir(const char *name_user, uint64_t mode) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    return do_mkdir(name, mode);
}

uint64_t sys_mkdirat(int dfd, const char *name_user, uint64_t mode) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    umode_t dir_mode = (umode_t)(mode & 0777);
    if (current_task && current_task->fs)
        dir_mode &= ~current_task->fs->umask;
    return (uint64_t)vfs_mkdirat((int)dfd, name, dir_mode);
}

uint64_t do_link(const char *name, const char *new) {
    return (uint64_t)vfs_linkat(AT_FDCWD, name, AT_FDCWD, new, 0);
}

static int parse_proc_self_fd_path(const char *path, int *fd_out) {
    if (!path || !fd_out)
        return 0;

    const char *fd_part = NULL;
    if (!strncmp(path, "/proc/self/fd/", strlen("/proc/self/fd/"))) {
        fd_part = path + strlen("/proc/self/fd/");
    } else if (!strncmp(path, "/proc/", strlen("/proc/"))) {
        const char *pid_part = path + strlen("/proc/");
        uint64_t pid = 0;
        if (!*pid_part)
            return 0;
        while (is_digit(*pid_part)) {
            pid = pid * 10 + (uint64_t)(*pid_part - '0');
            pid_part++;
        }
        if (pid != task_effective_tgid(current_task) ||
            strncmp(pid_part, "/fd/", strlen("/fd/"))) {
            return 0;
        }
        fd_part = pid_part + strlen("/fd/");
    } else {
        return 0;
    }

    if (!fd_part || !*fd_part)
        return 0;

    int fd = 0;
    while (is_digit(*fd_part)) {
        fd = fd * 10 + (*fd_part - '0');
        fd_part++;
    }
    if (*fd_part != '\0')
        return 0;

    *fd_out = fd;
    return 1;
}

static int resolve_linkat_source_path(uint64_t olddirfd, const char *oldpath,
                                      int flags, struct vfs_path *source_out) {
    if (!source_out)
        return -EINVAL;
    memset(source_out, 0, sizeof(*source_out));

    task_t *self = current_task;

    if ((flags & AT_EMPTY_PATH) && oldpath && oldpath[0] == '\0') {
        if (olddirfd >= MAX_FD_NUM || !self->fd_info->fds[olddirfd])
            return -EBADF;
        source_out->mnt = self->fd_info->fds[olddirfd]->f_path.mnt;
        source_out->dentry = self->fd_info->fds[olddirfd]->f_path.dentry;
        vfs_path_get(source_out);
        return 1;
    }

    if (flags & AT_SYMLINK_FOLLOW) {
        int fd = -1;
        if (parse_proc_self_fd_path(oldpath, &fd)) {
            if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
                return -ENOENT;
            source_out->mnt = self->fd_info->fds[fd]->f_path.mnt;
            source_out->dentry = self->fd_info->fds[fd]->f_path.dentry;
            vfs_path_get(source_out);
            return 1;
        }
    }

    return 0;
}

uint64_t sys_link(const char *name_user, const char *new_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    char new[512];
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;

    return do_link(name, new);
}

uint64_t do_symlink(const char *name, const char *new) {
    return (uint64_t)vfs_symlinkat(name, AT_FDCWD, new);
}

uint64_t sys_symlink(const char *name_user, const char *target_name_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    char target_name[512];
    if (copy_from_user_str(target_name, target_name_user, sizeof(target_name)))
        return (uint64_t)-EFAULT;

    return do_symlink(name, target_name);
}

uint64_t sys_linkat(uint64_t olddirfd, const char *oldpath_user,
                    uint64_t newdirfd, const char *newpath_user, int flags) {
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW))
        return (uint64_t)-EINVAL;

    char oldpath[512];
    if (copy_from_user_str(oldpath, oldpath_user, sizeof(oldpath)))
        return (uint64_t)-EFAULT;
    char newpath[512];
    if (copy_from_user_str(newpath, newpath_user, sizeof(newpath)))
        return (uint64_t)-EFAULT;

    struct vfs_path source = {0};
    int source_ret =
        resolve_linkat_source_path(olddirfd, oldpath, flags, &source);
    int ret = 0;

    if (source_ret < 0) {
        return (uint64_t)source_ret;
    }

    if (source_ret > 0) {
        ret = generic_link_pathat(&source, (int)newdirfd, newpath);
        vfs_path_put(&source);
    } else {
        ret = vfs_linkat((int)olddirfd, oldpath, (int)newdirfd, newpath,
                         flags & AT_SYMLINK_FOLLOW);
    }

    return ret;
}

uint64_t sys_symlinkat(const char *name_user, int dfd, const char *new_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    char new[512];
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;
    return (uint64_t)vfs_symlinkat(name, dfd, new);
}

uint64_t sys_mknod(const char *name_user, uint16_t umode, int dev) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    uint16_t masked_mode = (umode & S_IFMT) | (umode & 0777);
    if (current_task && current_task->fs)
        masked_mode =
            (umode & S_IFMT) | ((umode & 0777) & ~current_task->fs->umask);

    int ret = vfs_mknodat(AT_FDCWD, name, masked_mode, (dev64_t)dev);
    if (ret < 0)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_mknodat(uint64_t fd, const char *path_user, uint16_t umode,
                     int dev) {
    char path[512];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    uint16_t masked_mode = (umode & S_IFMT) | (umode & 0777);
    if (current_task && current_task->fs)
        masked_mode =
            (umode & S_IFMT) | ((umode & 0777) & ~current_task->fs->umask);

    int ret = vfs_mknodat((int)fd, path, masked_mode, (dev64_t)dev);
    if (ret < 0)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_chmod(const char *name_user, uint16_t mode) {
    struct vfs_path path = {0};
    int ret;
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&path, true, mode, false, 0, false, 0, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_fchmod(int fd, uint16_t mode) {
    struct vfs_path path = {0};
    int ret = generic_get_fd_path(fd, &path);
    if (ret < 0)
        return ret;
    ret = generic_setattr_path(&path, true, mode, false, 0, false, 0, false, 0);
    vfs_path_put(&path);
    return ret;
}

uint64_t sys_fchmodat(int dfd, const char *name_user, uint16_t mode) {
    struct vfs_path path = {0};
    int ret;
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(dfd, name, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&path, true, mode, false, 0, false, 0, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_fchmodat2(int dfd, const char *name_user, uint16_t mode,
                       int flags) {
    struct vfs_path path = {0};
    int ret;
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(
        dfd, name,
        (flags & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&path, true, mode, false, 0, false, 0, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_chown(const char *filename_user, uint64_t uid, uint64_t gid) {
    struct vfs_path path = {0};
    int ret;
    char filename[512];
    if (copy_from_user_str(filename, filename_user, sizeof(filename)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(AT_FDCWD, filename, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&path, false, 0, true, (uid32_t)uid, true,
                               (gid32_t)gid, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_fchown(int fd, uint64_t uid, uint64_t gid) {
    struct vfs_path path = {0};
    int ret = generic_get_fd_path(fd, &path);
    if (ret < 0)
        return ret;
    ret = generic_setattr_path(&path, false, 0, true, (uid32_t)uid, true,
                               (gid32_t)gid, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_fchownat(int dfd, const char *name_user, uint64_t uid,
                      uint64_t gid, int flags) {
    struct vfs_path path = {0};
    int ret;
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(
        dfd, name,
        (flags & AT_SYMLINK_NOFOLLOW) ? LOOKUP_NOFOLLOW : LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&path, false, 0, true, (uid32_t)uid, true,
                               (gid32_t)gid, false, 0);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len) {
    struct vfs_path path = {0};
    int ret;
    if (mode != 0)
        return -EOPNOTSUPP;
    if (offset > UINT64_MAX - len)
        return -EFBIG;
    ret = generic_get_fd_path(fd, &path);
    if (ret < 0)
        return ret;
    ret = generic_setattr_path(&path, false, 0, false, 0, false, 0, true,
                               offset + len);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_truncate(const char *path_user, uint64_t length) {
    struct vfs_path vpath = {0};
    int ret;
    char path[512];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;
    ret = vfs_filename_lookup(AT_FDCWD, path, LOOKUP_FOLLOW, &vpath);
    if (ret < 0)
        return (uint64_t)ret;
    ret = generic_setattr_path(&vpath, false, 0, false, 0, false, 0, true,
                               length);
    vfs_path_put(&vpath);
    return (uint64_t)ret;
}

uint64_t sys_ftruncate(int fd, uint64_t length) {
    struct vfs_path path = {0};
    int ret = generic_get_fd_path(fd, &path);
    if (ret < 0)
        return ret;
    ret =
        generic_setattr_path(&path, false, 0, false, 0, false, 0, true, length);
    vfs_path_put(&path);
    return (uint64_t)ret;
}

uint64_t sys_flock(int fd, uint64_t operation) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t *node = self->fd_info->fds[fd]->f_inode;
    vfs_bsd_lock_t *lock = &node->flock_lock;
    uint64_t pid = self->pid;

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
            arch_pause();
        }
        lock->l_type = (operation & LOCK_EX) ? F_WRLCK : F_RDLCK;
        lock->l_pid = pid;
        break;

    case LOCK_UN:
        if (lock->l_pid != pid)
            return -EACCES;
        lock->l_type = F_UNLCK;
        lock->l_pid = 0;
        break;
    }

    return 0;
}

uint64_t sys_fadvise64(int fd, uint64_t offset, uint64_t len, int advice) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
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

extern uint64_t memory_size;

uint64_t sys_sysinfo(struct sysinfo *info_user) {
    struct sysinfo res;
    struct sysinfo *info = &res;

    memset(info, 0, sizeof(struct sysinfo));
    info->uptime = boot_get_boottime();
    info->loads[0] = 0;
    info->loads[1] = 0;
    info->loads[2] = 0;
    info->totalram = memory_size / PAGE_SIZE;
    info->mem_unit = PAGE_SIZE;
    info->freeram = 0;
    info->procs = task_count();

    if (copy_to_user(info_user, info, sizeof(struct sysinfo)))
        return (uint64_t)-EFAULT;

    return 0;
}
