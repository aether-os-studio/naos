#include <init/abis.h>
#include <init/callbacks.h>
#include <fs/fs_syscall.h>
#include <fs/proc.h>
#include <boot/boot.h>
#include <net/socket.h>
#include <drivers/kernel_logger.h>
#include <task/task_syscall.h>

static uint64_t do_unlink(const char *name);
static uint64_t do_sys_open_tmpfile(const char *dir_path, uint64_t flags,
                                    uint64_t mode);
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
    if (!fd || !fd->node || !lock || !start_out || !end_out)
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
        base = (int64_t)fd->node->size;
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

    vfs_node_t *node = fd->node;
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

    vfs_node_t *node = fd->node;
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

uint64_t sys_mount(char *dev_name, char *dir_name, char *type_user,
                   uint64_t flags, void *data) {
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

    if (flags & MS_SLAVE) {
        return 0;
    }

    if (flags & MS_BIND) {
        return 0;
    }

    vfs_node_t *dir = vfs_open((const char *)dirname, 0);
    if (!dir) {
        return (uint64_t)-ENOENT;
    }

    if (flags & MS_MOVE) {
        if (flags & (MS_REMOUNT | MS_BIND)) {
            return (uint64_t)-EINVAL;
        }
        if (!current_task || !current_task->nsproxy ||
            !current_task->nsproxy->mnt_ns) {
            return (uint64_t)-EINVAL;
        }

        vfs_node_t *old_mount = vfs_open((const char *)devname, 0);
        if (!old_mount)
            return (uint64_t)-EINVAL;
        if (!(old_mount->type & file_dir))
            return (uint64_t)-ENOTDIR;

        struct mount_point *mnt = task_mnt_namespace_find_mount(
            current_task->nsproxy->mnt_ns, old_mount);
        if (!mnt)
            mnt = task_mnt_namespace_find_mount_by_root(
                current_task->nsproxy->mnt_ns, old_mount);
        if (!mnt)
            return (uint64_t)-EINVAL;
        if (mnt->dir == dir)
            return 0;
        if (vfs_is_ancestor(mnt->root_node, dir))
            return (uint64_t)-EINVAL;

        if (!(dir->type & file_dir))
            return (uint64_t)-ENOTDIR;

        return task_mnt_namespace_move_mount(current_task->nsproxy->mnt_ns,
                                             mnt->dir, dir);
    }

    if (flags & MS_REMOUNT) {
        if (flags & (MS_MOVE | MS_BIND))
            return (uint64_t)-EINVAL;
        if (!current_task || !current_task->nsproxy ||
            !current_task->nsproxy->mnt_ns)
            return (uint64_t)-EINVAL;
        if (!task_mnt_namespace_find_mount(current_task->nsproxy->mnt_ns, dir))
            return (uint64_t)-EINVAL;
        return 0;
    }

    if (dir == dir->root)
        return -EBUSY;

    uint64_t dev_nr = 0;
    vfs_node_t *dev = vfs_open((const char *)devname, 0);
    if (dev) {
        dev_nr = dev->rdev;
    }

    int ret = vfs_mount(dev_nr, dir, (const char *)type);
    if (ret < 0)
        return ret;
    if (current_task && current_task->nsproxy && current_task->nsproxy->mnt_ns)
        task_mnt_namespace_add_mount(current_task->nsproxy->mnt_ns,
                                     all_fs[dir->fsid], dir, dir, devname);
    return ret;
}

uint64_t sys_umount2(const char *target, uint64_t flags) {
    char target_k[512];
    if (copy_from_user_str(target_k, target, sizeof(target_k)))
        return (uint64_t)-EFAULT;

    vfs_node_t *node = vfs_open(target_k, 0);
    if (!node)
        return (uint64_t)-ENOENT;

    struct mount_point *mnt = NULL;
    if (current_task && current_task->nsproxy &&
        current_task->nsproxy->mnt_ns) {
        mnt =
            task_mnt_namespace_find_mount(current_task->nsproxy->mnt_ns, node);
        if (!mnt)
            mnt = task_mnt_namespace_find_mount_by_root(
                current_task->nsproxy->mnt_ns, node);
    }

    int ret = 0;
    if (mnt && mnt->root_node && mnt->root_node != node) {
        if (!mnt->fs || !mnt->fs->ops || !mnt->fs->ops->unmount)
            return (uint64_t)-EINVAL;
        mnt->fs->ops->unmount(mnt->root_node);
        vfs_close(mnt->root_node);
    } else {
        ret = vfs_unmount(target_k);
        if (ret < 0)
            return (uint64_t)ret;
    }

    if (current_task && current_task->nsproxy && current_task->nsproxy->mnt_ns)
        task_mnt_namespace_remove_mount(current_task->nsproxy->mnt_ns, node);
    return 0;
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
    if ((flags & O_TMPFILE) == O_TMPFILE)
        return do_sys_open_tmpfile(name, flags, mode);

    task_t *self = current_task;

    int create_mode = (flags & O_CREAT);
    uint64_t acc_mode = flags & O_ACCMODE_FLAGS;

    vfs_node_t *node = vfs_open(name, flags & O_NOFOLLOW);
    if (node && create_mode && (flags & O_EXCL)) {
        return (uint64_t)-EEXIST;
    }

    if (node && (flags & O_DIRECTORY) && !(node->type & file_dir)) {
        return (uint64_t)-ENOTDIR;
    }

    if (!node && ((flags & O_DIRECTORY) || !create_mode)) {
        return (uint64_t)-ENOENT;
    }

    if (!node) {
        int ret = vfs_mkfile(name);
        if (ret < 0) {
            if (ret == -EEXIST && !(flags & O_EXCL)) {
                node = vfs_open(name, flags & O_NOFOLLOW);
                if (node)
                    goto have_node;
            }
            return (uint64_t)ret;
        }

        node = vfs_open(name, flags & O_NOFOLLOW);
        if (!node)
            return (uint64_t)-ENOENT;
        if (mode) {
            uint16_t file_mode = mode & 0777;
            if (self && self->fs)
                file_mode &= ~self->fs->umask;
            vfs_chmod(name, file_mode);
        }
    }

have_node:
    if ((node->type & file_dir) &&
        (acc_mode == O_WRONLY || acc_mode == O_RDWR)) {
        return (uint64_t)-EISDIR;
    }

    if ((flags & O_TRUNC) && (node->type & file_none)) {
        vfs_resize(node, 0);
    }

    uint64_t ret = (uint64_t)-EMFILE;
    with_fd_info_lock(self->fd_info, {
        uint64_t i;
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (self->fd_info->fds[i] == NULL)
                break;
        }

        if (i == MAX_FD_NUM)
            break;

        fd_t *new_fd =
            fd_create(node, fd_open_file_flags(flags), !!(flags & O_CLOEXEC));
        if (!new_fd) {
            ret = (uint64_t)-ENOMEM;
            break;
        }
        self->fd_info->fds[i] = new_fd;
        vfs_node_ref_get(node);
        on_open_file_call(self, i);
        ret = i;
    });

    return ret;
}

static uint64_t do_sys_open_tmpfile(const char *dir_path, uint64_t flags,
                                    uint64_t mode) {
    if (!dir_path || !dir_path[0])
        return (uint64_t)-ENOENT;

    uint64_t acc_mode = flags & O_ACCMODE_FLAGS;
    if (acc_mode != O_WRONLY && acc_mode != O_RDWR)
        return (uint64_t)-EINVAL;

    vfs_node_t *dir = vfs_open(dir_path, flags & O_NOFOLLOW);
    if (!dir)
        return (uint64_t)-ENOENT;
    if (!(dir->type & file_dir))
        return (uint64_t)-ENOTDIR;

    const char *suffix = (dir_path[strlen(dir_path) - 1] == '/') ? "" : "/";
    char tmp_path[512];
    int pid = current_task ? current_task->pid : 0;

    for (int attempt = 0; attempt < 128; attempt++) {
        uint64_t seq =
            __atomic_fetch_add(&tmpfile_seq, 1, __ATOMIC_RELAXED) + attempt;
        int written =
            snprintf(tmp_path, sizeof(tmp_path), "%s%s.naos_tmpfile.%d.%llu",
                     dir_path, suffix, pid, (unsigned long long)seq);
        if (written <= 0 || (size_t)written >= sizeof(tmp_path))
            return (uint64_t)-ENAMETOOLONG;

        if (vfs_open(tmp_path, O_NOFOLLOW))
            continue;

        int mkret = vfs_mkfile(tmp_path);
        if (mkret == -EEXIST)
            continue;
        if (mkret < 0)
            return (uint64_t)mkret;

        if (mode) {
            uint16_t file_mode = mode & 0777;
            if (current_task && current_task->fs)
                file_mode &= ~current_task->fs->umask;
            vfs_chmod(tmp_path, file_mode);
        }

        uint64_t open_flags =
            flags & ~((uint64_t)O_TMPFILE | (uint64_t)O_DIRECTORY);
        uint64_t fd = do_sys_open(tmp_path, open_flags, mode);
        if ((int64_t)fd < 0) {
            do_unlink(tmp_path);
            return fd;
        }

        uint64_t unlink_ret = do_unlink(tmp_path);
        if ((int64_t)unlink_ret < 0) {
            sys_close(fd);
            return unlink_ret;
        }

        return fd;
    }

    return (uint64_t)-EEXIST;
}

uint64_t sys_open(const char *path, uint64_t flags, uint64_t mode) {
    char name[512];
    if (copy_from_user_str(name, path, sizeof(name)))
        return (uint64_t)-EFAULT;

    return do_sys_open(name, flags, mode);
}

uint64_t sys_openat(uint64_t dirfd, const char *name, uint64_t flags,
                    uint64_t mode) {
    char name_k[512];
    if (!name || copy_from_user_str(name_k, name, sizeof(name_k))) {
        return (uint64_t)-EFAULT;
    }
    char *path = at_resolve_pathname(dirfd, name_k);
    if (!path)
        return (uint64_t)-EINVAL;

    uint64_t ret = do_sys_open(path, flags, mode);

    free(path);

    return ret;
}

uint64_t sys_name_to_handle_at(int dfd, const char *name,
                               struct file_handle *handle, int *mnt_id,
                               int flag) {
    if (!name || !handle || check_user_overflow((uint64_t)name, 1) ||
        check_user_overflow((uint64_t)handle, sizeof(struct file_handle))) {
        return (uint64_t)-EFAULT;
    }

    char *path = at_resolve_pathname(dfd, (char *)name);
    if (!path) {
        return (uint64_t)-ENOMEM;
    }

    vfs_node_t *node = vfs_open(path, flag);
    free(path);

    if (!node) {
        return (uint64_t)-ENOENT;
    }

    const unsigned int required_size = sizeof(uint64_t);

    if (handle->handle_bytes < required_size) {
        handle->handle_bytes = required_size;
        return (uint64_t)-EOVERFLOW;
    }

    handle->handle_bytes = required_size;
    handle->handle_type = 1; // Generic file handle type

    if (check_user_overflow((uint64_t)handle->f_handle, required_size)) {
        return (uint64_t)-EFAULT;
    }

    if (copy_to_user(handle->f_handle, &node->inode, sizeof(uint64_t))) {
        return (uint64_t)-EFAULT;
    }

    if (mnt_id) {
        if (check_user_overflow((uint64_t)mnt_id, sizeof(int))) {
            return (uint64_t)-EFAULT;
        }
        int mount_id = (int)node->fsid;
        if (copy_to_user(mnt_id, &mount_id, sizeof(int))) {
            return (uint64_t)-EFAULT;
        }
    }

    return 0;
}

uint64_t sys_open_by_handle_at(int mountdirfd, struct file_handle *handle,
                               int flags) {
    if (!handle ||
        check_user_overflow((uint64_t)handle, sizeof(struct file_handle))) {
        return (uint64_t)-EFAULT;
    }

    struct file_handle user_handle;
    if (copy_from_user(&user_handle, handle, sizeof(struct file_handle))) {
        return (uint64_t)-EFAULT;
    }

    if (check_user_overflow((uint64_t)handle->f_handle,
                            user_handle.handle_bytes)) {
        return (uint64_t)-EFAULT;
    }

    uint64_t inode;
    if (copy_from_user(&inode, (const char *)handle->f_handle,
                       sizeof(uint64_t))) {
        return (uint64_t)-EFAULT;
    }

    vfs_node_t *node = vfs_find_node_by_inode(inode);
    if (!node) {
        return -ESTALE;
    }

    task_t *self = current_task;

    uint64_t ret = (uint64_t)-EMFILE;
    with_fd_info_lock(self->fd_info, {
        uint64_t i;
        for (i = 0; i < MAX_FD_NUM; i++) {
            if (self->fd_info->fds[i] == NULL)
                break;
        }

        if (i == MAX_FD_NUM)
            break;

        fd_t *new_fd =
            fd_create(node, fd_open_file_flags(flags), !!(flags & O_CLOEXEC));
        if (!new_fd) {
            ret = (uint64_t)-ENOMEM;
            break;
        }
        self->fd_info->fds[i] = new_fd;
        vfs_node_ref_get(node);
        on_open_file_call(self, i);
        ret = i;
    });

    return ret;
}

uint64_t sys_fsync(uint64_t fd) {
    task_t *self = current_task;

    if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t *node = self->fd_info->fds[fd]->node;

    return 0;
}

uint64_t sys_close(uint64_t fd) {
    if (fd == SPECIAL_FD)
        return 0;

    task_t *self = current_task;

    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;

    fd_t *entry = NULL;
    uint64_t ret = (uint64_t)-EBADF;
    with_fd_info_lock(self->fd_info, {
        entry = self->fd_info->fds[fd];
        if (!entry)
            break;

        file_lock_release_pid(entry->node, self->pid);
        if (entry->node->flock_lock.l_pid == self->pid) {
            entry->node->flock_lock.l_type = F_UNLCK;
            entry->node->flock_lock.l_pid = 0;
        }

        self->fd_info->fds[fd] = NULL;
        ret = 0;
    });

    if (ret)
        return ret;

    on_close_file_call(self, fd, entry);
    fd_release(entry);
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
                new_info->fds[i] = vfs_dup(old->fds[i]);
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
                entry->close_on_exec = true;
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

            file_lock_release_pid(entry->node, self->pid);
            if (entry->node->flock_lock.l_pid == self->pid) {
                entry->node->flock_lock.l_type = F_UNLCK;
                entry->node->flock_lock.l_pid = 0;
            }

            self->fd_info->fds[fd_] = NULL;
            to_close[fd_] = entry;
        }
    });

    for (uint64_t fd_ = fd; fd_ <= maxfd; fd_++) {
        fd_t *entry = to_close[fd_];
        if (!entry)
            continue;
        on_close_file_call(self, fd_, entry);
        fd_release(entry);
    }

    return 0;
}

uint64_t sys_copy_file_range(uint64_t fd_in, int *offset_in_user,
                             uint64_t fd_out, int *offset_out_user,
                             uint64_t len, uint64_t flags) {
    if (fd_in >= MAX_FD_NUM || fd_out >= MAX_FD_NUM) {
        return (uint64_t)-EBADF;
    }

    task_t *self = current_task;

    fd_t *in_fd = self->fd_info->fds[fd_in];
    fd_t *out_fd = self->fd_info->fds[fd_out];
    if (!in_fd || !out_fd) {
        return (uint64_t)-EBADF;
    }

    if (fd_get_offset(out_fd) >= out_fd->node->size && out_fd->node->size > 0)
        return 0;

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
        dst_offset = out_fd->node->size;

    vfs_node_t *in_node = vfs_get_real_node(in_fd->node);
    vfs_node_t *out_node = vfs_get_real_node(out_fd->node);

    uint64_t length = MIN(len, in_node->size);
    uint8_t *buffer = (uint8_t *)alloc_frames_bytes(length);
    size_t copy_total = 0;

    ssize_t ret = vfs_read(in_node, buffer, src_offset, length);
    if (ret < 0) {
        free_frames_bytes(buffer, length);
        return (uint64_t)-EIO;
    }

    if ((copy_total = vfs_write(out_node, buffer, dst_offset, ret)) ==
        (ssize_t)-1) {
        free_frames_bytes(buffer, length);
        return (uint64_t)-EIO;
    }
    vfs_update(out_fd->node);
    free_frames_bytes(buffer, length);
    if (!offset_in_user && copy_total > 0)
        fd_add_offset(in_fd, (int64_t)copy_total);
    if (!offset_out_user && copy_total > 0)
        fd_add_offset(out_fd, (int64_t)copy_total);

    return copy_total;
}

uint64_t sys_read(uint64_t fd, void *buf, uint64_t len) {
    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }
    task_t *self = current_task;

    ssize_t ret = 0;
    with_fd_info_lock(self->fd_info, {
        if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
            ret = -EBADF;
            break;
        }

        if (self->fd_info->fds[fd]->node->type & file_dir) {
            ret = -EISDIR;
            break;
        }

        fd_t *file = self->fd_info->fds[fd];
        ret = vfs_read_fd(file, buf, fd_get_offset(file), len);

        if (ret < 0)
            break;

        if (ret > 0) {
            fd_add_offset(file, ret);
        }
    });

    return ret;
}

uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len) {
    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    task_t *self = current_task;

    ssize_t ret = 0;
    with_fd_info_lock(self->fd_info, {
        if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
            ret = -EBADF;
            break;
        }

        if (self->fd_info->fds[fd]->node->type & file_dir) {
            ret = -EISDIR;
            break;
        }

        fd_t *file = self->fd_info->fds[fd];
        uint64_t write_offset = fd_get_offset(file);
        if (fd_get_flags(file) & O_APPEND)
            write_offset = file->node->size;
        ret = vfs_write_fd(file, buf, write_offset, len);

        if (ret < 0)
            break;

        if (ret > 0) {
            fd_add_offset(file, ret);
        }
    });

    return ret;
}

uint64_t sys_pread64(int fd, void *buf, size_t len, uint64_t offset) {
    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    task_t *self = current_task;

    ssize_t ret = 0;
    with_fd_info_lock(self->fd_info, {
        if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
            ret = -EBADF;
            break;
        }

        if (self->fd_info->fds[fd]->node->type & file_dir) {
            ret = -EISDIR;
            break;
        }

        ret = vfs_read_fd(self->fd_info->fds[fd], buf, offset, len);
    });

    return (uint64_t)ret;
}

uint64_t sys_pwrite64(int fd, const void *buf, size_t len, uint64_t offset) {
    if (!len) {
        return 0;
    }
    if (!buf || check_user_overflow((uint64_t)buf, len) ||
        check_unmapped((uint64_t)buf, len)) {
        return (uint64_t)-EFAULT;
    }

    task_t *self = current_task;

    ssize_t ret = 0;
    with_fd_info_lock(self->fd_info, {
        if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
            ret = -EBADF;
            break;
        }

        if (self->fd_info->fds[fd]->node->type & file_dir) {
            ret = -EISDIR;
            break;
        }

        ret = vfs_write_fd(self->fd_info->fds[fd], buf, offset, len);
    });

    return (uint64_t)ret;
}

uint64_t sys_sendfile(uint64_t out_fd, uint64_t in_fd, int *offset_ptr,
                      size_t count) {
    if (out_fd >= MAX_FD_NUM || in_fd >= MAX_FD_NUM)
        return -EBADF;

    task_t *self = current_task;

    fd_t *out_handle = self->fd_info->fds[out_fd];
    fd_t *in_handle = self->fd_info->fds[in_fd];
    if (out_handle == NULL || in_handle == NULL)
        return -EBADF;

    uint64_t current_offset =
        offset_ptr == NULL ? fd_get_offset(in_handle) : *offset_ptr;
    size_t total_sent = 0;

    size_t remaining = count;

    char *buffer = (char *)alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    if (buffer == NULL) {
        return -ENOMEM;
    }

    while (remaining > 0) {
        size_t bytes_to_read =
            remaining < DEFAULT_PAGE_SIZE ? remaining : DEFAULT_PAGE_SIZE;
        size_t bytes_read;
        size_t bytes_written;
        bytes_read =
            vfs_read_fd(in_handle, buffer, current_offset, bytes_to_read);
        if (bytes_read <= 0) {
            if (bytes_read == (size_t)-1 && total_sent == 0) {
                free_frames_bytes(buffer, DEFAULT_PAGE_SIZE);
                return -EIO;
            }
            break;
        }
        uint64_t out_offset = fd_get_offset(out_handle);
        if (fd_get_flags(out_handle) & O_APPEND)
            out_offset = out_handle->node->size;
        bytes_written =
            vfs_write_fd(out_handle, buffer, out_offset, bytes_read);
        if (bytes_written == (size_t)-1) {
            if (total_sent == 0) {
                free_frames_bytes(buffer, DEFAULT_PAGE_SIZE);
                return -EIO;
            }
            break;
        }
        if (bytes_written < bytes_read) {
            bytes_read = bytes_written;
        }
        current_offset += bytes_read;
        fd_add_offset(out_handle, bytes_read);
        total_sent += bytes_read;
        remaining -= bytes_read;
    }
    free_frames_bytes(buffer, DEFAULT_PAGE_SIZE);
    if (offset_ptr != NULL) {
        *offset_ptr = current_offset;
    } else {
        fd_set_offset(in_handle, current_offset);
    }
    return total_sent;
}

uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence) {
    task_t *self = current_task;

    whence &= 0xffffffff;

    if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    fd_t *file = self->fd_info->fds[fd];
    vfs_node_t *node = file->node;
    if (fd_get_flags(file) & O_PATH)
        return (uint64_t)-EBADF;
    if (node->type & (file_socket | file_fifo | file_stream)) {
        return (uint64_t)-ESPIPE;
    }

    int64_t signed_offset = (int64_t)offset;
    uint64_t new_offset = 0;
    int ret = 0;

    switch (whence) {
    case SEEK_SET:
        if (signed_offset < 0)
            return (uint64_t)-EINVAL;
        new_offset = (uint64_t)signed_offset;
        break;

    case SEEK_CUR: {
        if (fd_get_offset(file) > INT64_MAX)
            return (uint64_t)-EOVERFLOW;
        ret = lseek_add_offset((int64_t)fd_get_offset(file), signed_offset,
                               &new_offset);
        if (ret < 0)
            return (uint64_t)ret;
        break;
    }

    case SEEK_END: {
        if (node->size > INT64_MAX)
            return (uint64_t)-EOVERFLOW;
        ret = lseek_add_offset((int64_t)node->size, signed_offset, &new_offset);
        if (ret < 0)
            return (uint64_t)ret;
        break;
    }

    case SEEK_DATA:
    case SEEK_HOLE:
        if (signed_offset < 0)
            return (uint64_t)-EINVAL;
        /*
         * Linux allows a filesystem without sparse extent tracking to treat
         * the whole file as data and EOF as the implicit hole.
         */
        if (offset >= node->size)
            return (uint64_t)-ENXIO;
        new_offset = whence == SEEK_DATA ? offset : node->size;
        break;

    default:
        return (uint64_t)-EINVAL;
    }

    fd_set_offset(file, new_offset);
    return fd_get_offset(file);
}

uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg) {
    task_t *self = current_task;

    if (fd >= MAX_FD_NUM || self->fd_info->fds[fd] == NULL) {
        return (uint64_t)-EBADF;
    }

    fd_t *f = self->fd_info->fds[fd];

    if (fd_get_flags(f) & O_PATH) {
        return (uint64_t)-EBADF;
    }

    int ret = -ENOSYS;
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
        if (f->node->type & file_socket) {
            ret = vfs_ioctl(f, cmd, arg);
            if (ret == -ENOTTY || ret == -ENOSYS)
                ret = 0;
        }
        break;
    case FIOCLEX:
        f->close_on_exec = true;
        ret = 0;
        break;
    case FIONCLEX:
        f->close_on_exec = false;
        ret = 0;
        break;

    default:
        ret = vfs_ioctl(f, cmd, arg);
        if ((cmd == TCGETS || cmd == TCSETS || cmd == TCGETS2 ||
             cmd == TIOCSCTTY || cmd == TIOCGWINSZ) &&
            ret < 0) {
            ret = -ENOTTY;
        }
        break;
    }
    if (ret == -ENOSYS) {
        printk("sys_ioctl: cmd %#010x not implemented, fs = %s\n", cmd,
               all_fs[f->node->fsid] ? all_fs[f->node->fsid]->name : NULL);
    }

    return ret;
}

uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count) {
    if (!iovec ||
        check_user_overflow((uint64_t)iovec, count * sizeof(struct iovec))) {
        return (uint64_t)-EFAULT;
    }

    ssize_t total_read = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (iovec[i].iov_base == NULL || iovec[i].len == 0)
            continue;

        ssize_t ret = sys_read(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0) {
            if (total_read > 0 &&
                (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR)) {
                return total_read;
            }
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

    ssize_t total_written = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (iovec[i].iov_base == NULL || iovec[i].len == 0)
            continue;

        ssize_t ret = sys_write(fd, iovec[i].iov_base, iovec[i].len);
        if (ret < 0) {
            if (total_written > 0 &&
                (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -EINTR)) {
                return total_written;
            }
            return (uint64_t)ret;
        }
        total_written += ret;
        if ((size_t)ret < iovec[i].len)
            break;
    }
    return total_written;
}

#define DIRENT_HEADER_SIZE offsetof(struct dirent, d_name)

static inline size_t dirent_reclen(size_t name_len) {
    return (DIRENT_HEADER_SIZE + name_len + 1 + 7) & ~7;
}

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size) {
    if (check_user_overflow(buf, size) || check_unmapped(buf, size)) {
        return (uint64_t)-EFAULT;
    }
    if (fd >= MAX_FD_NUM)
        return (uint64_t)-EBADF;
    task_t *self = current_task;
    if (!self->fd_info->fds[fd])
        return (uint64_t)-EBADF;
    if (!(self->fd_info->fds[fd]->node->type & file_dir))
        return (uint64_t)-ENOTDIR;

    fd_t *filedescriptor = self->fd_info->fds[fd];
    vfs_node_t *node = filedescriptor->node;

    uint8_t *buf_ptr = (uint8_t *)buf;
    uint64_t bytes_written = 0;

    uint64_t entry_index = 0;

    vfs_node_t *child_node, *tmp;
    llist_for_each(child_node, tmp, &node->childs, node_for_childs) {
        if (entry_index < fd_get_offset(filedescriptor)) {
            entry_index++;
            continue;
        }

        size_t name_len = strlen(child_node->name);
        if (name_len > 255)
            name_len = 255;
        size_t reclen = dirent_reclen(name_len);

        if (bytes_written + reclen > size) {
            if (bytes_written == 0)
                return (uint64_t)-EINVAL;
            break;
        }

        struct dirent *dent = (struct dirent *)(buf_ptr + bytes_written);

        memset(dent, 0, reclen);

        dent->d_ino = child_node->inode;
        dent->d_reclen = reclen;

        dent->d_off = entry_index + 1;

        if (child_node->type & file_symlink)
            dent->d_type = DT_LNK;
        else if (child_node->type & file_none)
            dent->d_type = DT_REG;
        else if (child_node->type & file_dir)
            dent->d_type = DT_DIR;
        else if (child_node->type & file_block)
            dent->d_type = DT_BLK;
        else
            dent->d_type = DT_UNKNOWN;

        memcpy(dent->d_name, child_node->name, name_len + 1);

        bytes_written += reclen;

        fd_set_offset(filedescriptor, entry_index + 1);

        entry_index++;
    }

    return bytes_written;
}

uint64_t sys_chdir(const char *dname) {
    char dirname[512];

    if (copy_from_user_str(dirname, dname, sizeof(dirname)))
        return (uint64_t)-EFAULT;

    vfs_node_t *new_cwd = vfs_open(dirname, 0);
    if (!new_cwd)
        return (uint64_t)-ENOENT;
    if (new_cwd->type & file_symlink) {
        new_cwd = vfs_get_real_node(new_cwd);
    }
    if (!(new_cwd->type & file_dir))
        return (uint64_t)-ENOTDIR;

    return task_fs_chdir(current_task, new_cwd);
}

uint64_t sys_chroot(const char *dname) {
    char dirname[512];

    if (copy_from_user_str(dirname, dname, sizeof(dirname)))
        return (uint64_t)-EFAULT;

    vfs_node_t *new_root = vfs_open(dirname, 0);
    if (!new_root)
        return (uint64_t)-ENOENT;
    if (new_root->type & file_symlink)
        new_root = vfs_get_real_node(new_root);
    if (!(new_root->type & file_dir))
        return (uint64_t)-ENOTDIR;

    int ret = task_fs_chroot(current_task, new_root);
    if (ret < 0)
        return (uint64_t)ret;

    if (!vfs_is_ancestor(new_root, task_fs_cwd(current_task))) {
        task_fs_chdir(current_task, new_root);
    }

    return 0;
}

uint64_t sys_getcwd(char *cwd, uint64_t size) {
    char *str = vfs_get_fullpath_at(task_fs_cwd(current_task),
                                    task_fs_root(current_task));
    if (size < (uint64_t)strlen(str)) {
        return (uint64_t)-ERANGE;
    }
    uint64_t to_copy = strlen(str);
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

        fd_t *newf = vfs_dup(self->fd_info->fds[fd]);
        if (!newf) {
            ret = (uint64_t)-ENOSPC;
            break;
        }

        if (self->fd_info->fds[newfd]) {
            replaced_fd = self->fd_info->fds[newfd];
            self->fd_info->fds[newfd] = NULL;
            replaced_existing = true;
        }

        newf->close_on_exec = false;
        if (cloexec) {
            newf->close_on_exec = true;
        }

        self->fd_info->fds[newfd] = newf;
        installed_new = true;
    });

    if ((int64_t)ret >= 0 && installed_new) {
        if (replaced_existing) {
            on_close_file_call(self, newfd, replaced_fd);
            fd_release(replaced_fd);
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

        fd_t *newf = vfs_dup(self->fd_info->fds[fd]);
        if (!newf) {
            ret = (uint64_t)-ENOSPC;
            break;
        }

        newf->close_on_exec = false;
        if (cloexec) {
            newf->close_on_exec = true;
        }

        self->fd_info->fds[i] = newf;
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
    if (fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return (uint64_t)-EBADF;

    uint64_t i;

    switch (command) {
    case F_GETFD:
        return self->fd_info->fds[fd]->close_on_exec ? FD_CLOEXEC : 0;
    case F_SETFD:
        bool close_on_exec = !!(arg & FD_CLOEXEC);
        self->fd_info->fds[fd]->close_on_exec = close_on_exec;
        return 0;
    case F_DUPFD_CLOEXEC:
        return dup_to_free_slot(self, fd, arg, true);
    case F_DUPFD:
        return dup_to_free_slot(self, fd, arg, false);
    case F_GETFL:
        return fd_get_flags(self->fd_info->fds[fd]);
    case F_SETFL:
        if (fd_get_flags(self->fd_info->fds[fd]) & O_PATH)
            return (uint64_t)-EBADF;
        uint64_t file_flags = fd_get_flags(self->fd_info->fds[fd]);
        uint64_t valid_flags = O_SETFL_FLAGS;
        file_flags &= ~valid_flags;
        file_flags |= arg & valid_flags;
        fd_set_flags(self->fd_info->fds[fd], file_flags);
        int ret = 0;
        if (self->fd_info->fds[fd]->node->type & file_socket) {
            int nonblock = !!(file_flags & O_NONBLOCK);
            ret =
                vfs_ioctl(self->fd_info->fds[fd], FIONBIO, (ssize_t)&nonblock);
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
        int getlk_ret = file_lock_getlk(self->fd_info->fds[fd], &lock);
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

        return file_lock_setlk(self->fd_info->fds[fd], &lock,
                               command == F_SETLKW);
    }
    case F_GETPIPE_SZ:
        return 512 * 1024;
    case F_SETPIPE_SZ:
        return 0;
    case F_GET_SEALS:
    case F_ADD_SEALS:
        return 0;
    case F_GET_RW_HINT:
        if (!self->fd_info->fds[fd]->node->rw_hint) {
            return 0;
        }
        return self->fd_info->fds[fd]->node->rw_hint;

    case F_SET_RW_HINT:
        if (arg < RWH_WRITE_LIFE_NONE || arg > RWH_WRITE_LIFE_EXTREME) {
            return -EINVAL;
        }
        self->fd_info->fds[fd]->node->rw_hint = arg;
        return 0;
    default:
        printk("Unsupported fcntl command %#010lx\n", command);
        return (uint64_t)-EINVAL;
    }
}

uint64_t do_stat_path(const char *path, struct stat *buf) {
    memset(buf, 0, sizeof(struct stat));

    vfs_node_t *node = vfs_open(path, O_NOFOLLOW);
    if (!node) {
        // serial_fprintk("Stating file %s failed\n", path);
        return (uint64_t)-ENOENT;
    }

    buf->st_dev = node->dev;
    buf->st_ino = node->inode;
    buf->st_nlink = 1;
    buf->st_mode = node->mode;
    if (node->type & file_symlink)
        buf->st_mode |= S_IFLNK;
    else if (node->type & file_block)
        buf->st_mode |= S_IFBLK;
    else if (node->type & file_stream)
        buf->st_mode |= S_IFCHR;
    else if (node->type & file_fifo)
        buf->st_mode |= S_IFIFO;
    else if (node->type & file_socket)
        buf->st_mode |= S_IFSOCK;
    else if (node->type & file_dir)
        buf->st_mode |= S_IFDIR;
    else if (node->type & file_none)
        buf->st_mode |= S_IFREG;
    buf->st_uid = node->owner;
    buf->st_gid = node->group;
    buf->st_rdev = node->rdev;
    buf->st_blksize = node->blksz;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

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
    memset(buf, 0, sizeof(struct stat));

    task_t *self = current_task;
    vfs_node_t *node = self->fd_info->fds[fd]->node;

    vfs_update(node);

    buf->st_dev = node->dev;
    buf->st_ino = node->inode;
    buf->st_nlink = 1;
    buf->st_mode = node->mode;
    if (node->type & file_symlink)
        buf->st_mode |= S_IFLNK;
    else if (node->type & file_block)
        buf->st_mode |= S_IFBLK;
    else if (node->type & file_stream)
        buf->st_mode |= S_IFCHR;
    else if (node->type & file_fifo)
        buf->st_mode |= S_IFIFO;
    else if (node->type & file_socket)
        buf->st_mode |= S_IFSOCK;
    else if (node->type & file_dir)
        buf->st_mode |= S_IFDIR;
    else if (node->type & file_none)
        buf->st_mode |= S_IFREG;
    buf->st_uid = node->owner;
    buf->st_gid = node->group;
    buf->st_rdev = node->rdev;
    buf->st_blksize = node->blksz;
    buf->st_size = node->size;
    buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;

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

    if (flags & AT_EMPTY_PATH) {
        return sys_fstat(dirfd, buf_user);
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);

    if (!resolved) {
        return (uint64_t)-EINVAL;
    }

    struct stat buf;
    uint64_t ret = do_stat_path(resolved, &buf);

    free(resolved);

    if ((int64_t)ret < 0)
        return ret;

    if (copy_to_user(buf_user, &buf, sizeof(struct stat)))
        return (uint64_t)-EFAULT;

    return 0;
}

uint64_t sys_statx(uint64_t dirfd, const char *pathname_user, uint64_t flags,
                   uint64_t mask, struct statx *buff_user) {
    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    struct stat simple;

    struct statx res;
    struct statx *buff = &res;

    task_t *self = current_task;

    if (flags & AT_EMPTY_PATH) {
        if (dirfd >= MAX_FD_NUM || !self->fd_info->fds[dirfd])
            return (uint64_t)-EBADF;
        int ret = do_stat_fd(dirfd, &simple);
        if (ret < 0)
            return ret;
        buff->stx_mnt_id = self->fd_info->fds[dirfd]->node->fsid;
    } else {
        char *resolved = at_resolve_pathname(dirfd, (char *)pathname);

        if (!resolved) {
            return (uint64_t)-EINVAL;
        }

        uint64_t ret = do_stat_path(resolved, &simple);

        vfs_node_t *node = vfs_open(resolved, O_NOFOLLOW);

        free(resolved);

        if (!node)
            return (uint64_t)-ENOENT;

        if ((int64_t)ret < 0)
            return ret;

        buff->stx_mnt_id = node->fsid;
    }

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

    buff->stx_dev_major = (simple.st_dev >> 8) & 0xFF;
    buff->stx_dev_minor = simple.st_dev & 0xFF;
    buff->stx_rdev_major = (simple.st_rdev >> 8) & 0xFF;
    buff->stx_rdev_minor = simple.st_rdev & 0xFF;

    buff->stx_atime.tv_sec = simple.st_atim.tv_sec;
    buff->stx_atime.tv_nsec = simple.st_atim.tv_nsec;

    buff->stx_btime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_btime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_ctime.tv_sec = simple.st_ctim.tv_sec;
    buff->stx_ctime.tv_nsec = simple.st_ctim.tv_nsec;

    buff->stx_mtime.tv_sec = simple.st_mtim.tv_sec;
    buff->stx_mtime.tv_nsec = simple.st_mtim.tv_nsec;

    // todo: special devices

    if (copy_to_user(buff_user, buff, sizeof(struct statx)))
        return (uint64_t)-EFAULT;

    return 0;
}

size_t do_access(char *filename, int mode) {
    struct stat tmp;
    return do_stat_path(filename, &tmp);
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
    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    if (pathname[0] == '\0') { // by fd
        return 0;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = do_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname_user,
                        uint64_t mode, uint64_t flags) {
    char pathname[512];
    if (copy_from_user_str(pathname, pathname_user, sizeof(pathname)))
        return (uint64_t)-EFAULT;

    if (pathname[0] == '\0') { // by fd
        return 0;
    }

    char *resolved = at_resolve_pathname(dirfd, (char *)pathname);
    if (resolved == NULL)
        return (uint64_t)-ENOENT;

    size_t ret = do_access(resolved, mode);

    free(resolved);

    return ret;
}

uint64_t do_readlink(char *path, char *buf, uint64_t size) {
    vfs_node_t *node = vfs_open(path, O_NOFOLLOW);
    if (node == NULL) {
        return (uint64_t)-ENOENT;
    }

    if (!(node->type & file_symlink)) {
        return (uint64_t)-EINVAL;
    }

    ssize_t result = vfs_readlink(node, buf, (size_t)size);

    return result;
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
    if (path_user == NULL || buf_user == NULL || size == 0) {
        return (uint64_t)-EFAULT;
    }

    char path[512];

    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    char *resolved = at_resolve_pathname(dfd, path);
    if (!resolved)
        return (uint64_t)-ENOENT;

    char *buf = malloc(size);
    if (!buf) {
        free(resolved);
        return (uint64_t)-ENOMEM;
    }
    memset(buf, 0, size);

    ssize_t res = do_readlink(resolved, buf, size);

    free(resolved);

    if (res < 0) {
        free(buf);
        return (uint64_t)res;
    }

    if (copy_to_user(buf_user, buf, res)) {
        free(buf);
        return (uint64_t)-EFAULT;
    }

    free(buf);

    return res;
}

uint64_t sys_rmdir(const char *name_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name))) {
        return (uint64_t)-EFAULT;
    }

    vfs_node_t *node = vfs_open(name, O_NOFOLLOW);
    if (!node)
        return -ENOENT;
    if (!(node->type & file_dir))
        return -ENOTDIR;

    if (node == node->root) {
        return -EBUSY;
    }

    uint64_t ret = vfs_delete(node);

    return ret;
}

static uint64_t do_unlink(const char *name) {
    vfs_node_t *node = vfs_open(name, O_NOFOLLOW);
    if (!node)
        return -ENOENT;

    uint64_t ret = vfs_delete(node);

    return ret;
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

    char *path = at_resolve_pathname(dirfd, (char *)name);
    if (!path)
        return -ENOENT;

    uint64_t ret = do_unlink((const char *)path);

    free(path);

    return ret;
}

uint64_t do_rename(const char *old, const char *new) {
    vfs_node_t *node = vfs_open(old, O_NOFOLLOW);
    if (!node)
        return -ENOENT;
    int ret = vfs_rename(node, new);
    if (ret < 0)
        return ret;

    return 0;
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

    char *old_path = at_resolve_pathname_fullpath(oldfd, (char *)old);
    char *new_path = at_resolve_pathname_fullpath(newfd, (char *)new);
    if (!old_path || !new_path) {
        free(old_path);
        free(new_path);
        return (uint64_t)-EBADF;
    }

    int ret = do_rename(old_path, new_path);

    free(old_path);
    free(new_path);

    return ret;
}

uint64_t sys_renameat2(uint64_t oldfd, const char *old_user, uint64_t newfd,
                       const char *new_user, uint64_t flags) {
    char old[512];
    char new[512];

    if (copy_from_user_str(old, old_user, sizeof(old)))
        return (uint64_t)-EFAULT;
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;

    char *old_path = at_resolve_pathname_fullpath(oldfd, (char *)old);
    char *new_path = at_resolve_pathname_fullpath(newfd, (char *)new);
    if (!old_path || !new_path) {
        free(old_path);
        free(new_path);
        return (uint64_t)-EBADF;
    }

    int ret = do_rename(old_path, new_path);

    free(old_path);
    free(new_path);

    return ret;
}

uint64_t sys_fchdir(uint64_t fd) {
    task_t *self = current_task;

    if (fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t *node = self->fd_info->fds[fd]->node;
    if (!(node->type & file_dir))
        return -ENOTDIR;

    return task_fs_chdir(self, node);
}

uint64_t do_mkdir(const char *name, uint64_t mode) {
    int ret = vfs_mkdir(name);
    if (ret < 0) {
        return (uint64_t)ret;
    }
    uint16_t dir_mode = mode & 0777;
    if (current_task && current_task->fs)
        dir_mode &= ~current_task->fs->umask;
    vfs_chmod(name, dir_mode);

    return 0;
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

    char *path = at_resolve_pathname(dfd, name);

    uint64_t ret = do_mkdir((const char *)path, mode);

    free(path);

    return ret;
}

uint64_t do_link(const char *name, const char *new) {
    return vfs_link(new, name);
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

static int resolve_linkat_source_node(uint64_t olddirfd, const char *oldpath,
                                      int flags, vfs_node_t **source_out) {
    if (!source_out)
        return -EINVAL;
    *source_out = NULL;

    task_t *self = current_task;

    if ((flags & AT_EMPTY_PATH) && oldpath && oldpath[0] == '\0') {
        if (olddirfd >= MAX_FD_NUM || !self->fd_info->fds[olddirfd])
            return -EBADF;
        *source_out = self->fd_info->fds[olddirfd]->node;
        return 1;
    }

    if (flags & AT_SYMLINK_FOLLOW) {
        int fd = -1;
        if (parse_proc_self_fd_path(oldpath, &fd)) {
            if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
                return -ENOENT;
            *source_out = self->fd_info->fds[fd]->node;
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
    return vfs_symlink(new, name);
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

    char *new = at_resolve_pathname_fullpath(newdirfd, newpath);
    if (!new) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t *source = NULL;
    int source_ret =
        resolve_linkat_source_node(olddirfd, oldpath, flags, &source);
    int ret = 0;

    if (source_ret < 0) {
        free(new);
        return (uint64_t)source_ret;
    }

    if (source_ret > 0) {
        ret = vfs_link_existing(new, source);
    } else {
        char *old = at_resolve_pathname_fullpath(olddirfd, oldpath);
        if (!old) {
            free(new);
            return (uint64_t)-EBADF;
        }

        ret = do_link(old, new);
        free(old);
    }

    free(new);

    return ret;
}

uint64_t sys_symlinkat(const char *name_user, int dfd, const char *new_user) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;
    char new[512];
    if (copy_from_user_str(new, new_user, sizeof(new)))
        return (uint64_t)-EFAULT;
    char *buf = at_resolve_pathname_fullpath(dfd, new);
    if (!buf) {
        return (uint64_t)-EBADF;
    }

    int ret = do_symlink(name, buf);

    free(buf);

    return ret;
}

uint64_t sys_mknod(const char *name_user, uint16_t umode, int dev) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    uint16_t masked_mode = (umode & S_IFMT) | (umode & 0777);
    if (current_task && current_task->fs)
        masked_mode =
            (umode & S_IFMT) | ((umode & 0777) & ~current_task->fs->umask);

    int ret = vfs_mknod(name, masked_mode, dev);
    if (ret < 0)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_mknodat(uint64_t fd, const char *path_user, uint16_t umode,
                     int dev) {
    char path[512];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    char *fullpath = at_resolve_pathname(fd, path);
    uint16_t masked_mode = (umode & S_IFMT) | (umode & 0777);
    if (current_task && current_task->fs)
        masked_mode =
            (umode & S_IFMT) | ((umode & 0777) & ~current_task->fs->umask);

    int ret = vfs_mknod(fullpath, masked_mode, dev);
    free(fullpath);
    if (ret < 0)
        return (uint64_t)-EINVAL;

    return 0;
}

uint64_t sys_chmod(const char *name_user, uint16_t mode) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    return vfs_chmod(name, mode);
}

uint64_t sys_fchmod(int fd, uint16_t mode) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    int ret = vfs_fchmod(self->fd_info->fds[fd], mode);
    return ret;
}

uint64_t sys_fchmodat(int dfd, const char *name_user, uint16_t mode) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    char *resolved = at_resolve_pathname(dfd, name);
    int ret = vfs_chmod(name, mode);
    free(resolved);
    return ret;
}

uint64_t sys_fchmodat2(int dfd, const char *name_user, uint16_t mode,
                       int flags) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    char *resolved = at_resolve_pathname(dfd, name);
    int ret = vfs_chmod(name, mode);
    free(resolved);
    return ret;
}

uint64_t sys_chown(const char *filename_user, uint64_t uid, uint64_t gid) {
    char filename[512];
    if (copy_from_user_str(filename, filename_user, sizeof(filename)))
        return (uint64_t)-EFAULT;

    int ret = vfs_chown(filename, uid, gid);
    return ret;
}

uint64_t sys_fchown(int fd, uint64_t uid, uint64_t gid) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t *node = self->fd_info->fds[fd]->node;

    char *fullpath = vfs_get_fullpath_at(node, self->fs->root);
    int ret = vfs_chown(fullpath, uid, gid);
    free(fullpath);
    return ret;
}

uint64_t sys_fchownat(int dfd, const char *name_user, uint64_t uid,
                      uint64_t gid, int flags) {
    char name[512];
    if (copy_from_user_str(name, name_user, sizeof(name)))
        return (uint64_t)-EFAULT;

    char *resolved = at_resolve_pathname(dfd, name);
    vfs_chown((const char *)resolved, uid, gid);
    free(resolved);
    return 0;
}

uint64_t sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t *node = self->fd_info->fds[fd]->node;

    vfs_resize(node, offset + len);

    return 0;
}

uint64_t sys_truncate(const char *path_user, uint64_t length) {
    char path[512];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    vfs_node_t *node = vfs_open(path, 0);
    if (!node) {
        return (uint64_t)-ENOENT;
    }

    vfs_resize(node, length);

    return 0;
}

uint64_t sys_ftruncate(int fd, uint64_t length) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_resize(self->fd_info->fds[fd]->node, length);

    return 0;
}

uint64_t sys_flock(int fd, uint64_t operation) {
    task_t *self = current_task;

    if (fd < 0 || fd >= MAX_FD_NUM || !self->fd_info->fds[fd])
        return -EBADF;

    vfs_node_t *node = self->fd_info->fds[fd]->node;
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
    info->totalram = memory_size / DEFAULT_PAGE_SIZE;
    info->mem_unit = DEFAULT_PAGE_SIZE;
    info->freeram = 0;
    info->procs = task_count();

    if (copy_to_user(info_user, info, sizeof(struct sysinfo)))
        return (uint64_t)-EFAULT;

    return 0;
}
