#include <arch/arch.h>
#include <task/task.h>
#include <task/signal.h>
#include <fs/pipe.h>
#include <fs/vfs/vfs.h>
#include <init/callbacks.h>

#define PIPEFS_MAGIC 0x50495045ULL

typedef struct pipefs_fs_info {
    spinlock_t lock;
    ino64_t next_ino;
} pipefs_fs_info_t;

typedef struct pipefs_inode_info {
    struct vfs_inode vfs_inode;
} pipefs_inode_info_t;

static struct vfs_file_system_type pipefs_fs_type;
static const struct vfs_super_operations pipefs_super_ops;
static const struct vfs_file_operations pipefs_dir_file_ops;
static const struct vfs_file_operations pipefs_file_ops;
static mutex_t pipefs_mount_lock;
static struct vfs_mount *pipefs_internal_mnt;

int pipefs_id = 0;

static inline pipefs_fs_info_t *pipefs_sb_info(struct vfs_super_block *sb) {
    return sb ? (pipefs_fs_info_t *)sb->s_fs_info : NULL;
}

static inline pipe_specific_t *pipefs_spec_from_inode(struct vfs_inode *inode) {
    return inode ? (pipe_specific_t *)inode->i_private : NULL;
}

static inline pipe_specific_t *pipefs_spec_from_file(struct vfs_file *file) {
    if (!file)
        return NULL;
    if (file->private_data)
        return (pipe_specific_t *)file->private_data;
    return pipefs_spec_from_inode(file->f_inode);
}

static pipe_info_t *pipefs_named_info(struct vfs_inode *inode) {
    return inode ? (pipe_info_t *)inode->i_private : NULL;
}

static pipe_info_t *pipefs_alloc_info(void) {
    pipe_info_t *info = calloc(1, sizeof(*info));

    if (!info)
        return NULL;

    info->buf = malloc(PIPE_BUFF);
    if (!info->buf) {
        free(info);
        return NULL;
    }

    memset(info->buf, 0, PIPE_BUFF);
    spin_init(&info->lock);
    return info;
}

static pipe_info_t *pipefs_named_ensure_info(struct vfs_inode *inode) {
    pipe_info_t *pipe;
    pipe_info_t *new_pipe;
    pipe_info_t *expected = NULL;

    if (!inode)
        return NULL;

    pipe = pipefs_named_info(inode);
    if (pipe)
        return pipe;

    new_pipe = pipefs_alloc_info();
    if (!new_pipe)
        return NULL;

    new_pipe->read_node = inode;
    new_pipe->write_node = inode;

    if (!__atomic_compare_exchange_n((pipe_info_t **)&inode->i_private,
                                     &expected, new_pipe, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        free(new_pipe->buf);
        free(new_pipe);
        pipe = expected;
    } else {
        pipe = new_pipe;
    }

    if (pipe) {
        pipe->read_node = inode;
        pipe->write_node = inode;
    }
    return pipe;
}

static struct vfs_inode *pipefs_alloc_inode(struct vfs_super_block *sb) {
    pipefs_inode_info_t *info = calloc(1, sizeof(*info));

    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void pipefs_destroy_inode(struct vfs_inode *inode) {
    if (!inode)
        return;
    free(container_of(inode, pipefs_inode_info_t, vfs_inode));
}

static void pipefs_evict_inode(struct vfs_inode *inode) {
    pipe_specific_t *spec = pipefs_spec_from_inode(inode);
    pipe_info_t *pipe;
    bool free_pipe = false;

    if (!spec)
        return;

    pipe = spec->info;
    if (pipe) {
        spin_lock(&pipe->lock);
        if (spec->write) {
            if (pipe->write_node == inode)
                pipe->write_node = NULL;
        } else {
            if (pipe->read_node == inode)
                pipe->read_node = NULL;
        }
        if (!pipe->read_node && !pipe->write_node)
            free_pipe = true;
        spin_unlock(&pipe->lock);
    }

    free(spec);
    inode->i_private = NULL;

    if (free_pipe && pipe) {
        free(pipe->buf);
        free(pipe);
    }
}

static int pipefs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int pipefs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    pipefs_fs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *root;

    if (!fc)
        return -EINVAL;

    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb)
        return -ENOMEM;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    sb->s_magic = PIPEFS_MAGIC;
    sb->s_fs_info = fsi;
    sb->s_op = &pipefs_super_ops;
    sb->s_type = &pipefs_fs_type;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->inode = 1;
    inode->i_mode = S_IFDIR | 0700;
    inode->type = file_dir;
    inode->i_nlink = 2;
    inode->i_fop = &pipefs_dir_file_ops;

    root = vfs_d_alloc(sb, NULL, NULL);
    if (!root) {
        vfs_iput(inode);
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root, inode);
    sb->s_root = root;
    fc->sb = sb;
    return 0;
}

static void pipefs_put_super(struct vfs_super_block *sb) {
    if (!sb)
        return;
    free(sb->s_fs_info);
    sb->s_fs_info = NULL;
}

static const struct vfs_super_operations pipefs_super_ops = {
    .alloc_inode = pipefs_alloc_inode,
    .destroy_inode = pipefs_destroy_inode,
    .evict_inode = pipefs_evict_inode,
    .put_super = pipefs_put_super,
};

static struct vfs_file_system_type pipefs_fs_type = {
    .name = "pipefs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = pipefs_init_fs_context,
    .get_tree = pipefs_get_tree,
};

static struct vfs_mount *pipefs_get_internal_mount(void) {
    int ret;

    mutex_lock(&pipefs_mount_lock);
    if (!pipefs_internal_mnt) {
        ret = vfs_kern_mount("pipefs", 0, NULL, NULL, &pipefs_internal_mnt);
        if (ret < 0)
            pipefs_internal_mnt = NULL;
    }
    if (pipefs_internal_mnt)
        vfs_mntget(pipefs_internal_mnt);
    mutex_unlock(&pipefs_mount_lock);
    return pipefs_internal_mnt;
}

static ino64_t pipefs_next_ino(struct vfs_super_block *sb) {
    pipefs_fs_info_t *fsi = pipefs_sb_info(sb);
    ino64_t ino;

    spin_lock(&fsi->lock);
    ino = ++fsi->next_ino;
    spin_unlock(&fsi->lock);
    return ino;
}

static loff_t pipefs_llseek(struct vfs_file *file, loff_t offset, int whence) {
    loff_t pos;

    if (!file || !file->f_inode)
        return -EBADF;

    mutex_lock(&file->f_pos_lock);
    switch (whence) {
    case SEEK_SET:
        pos = offset;
        break;
    case SEEK_CUR:
        pos = file->f_pos + offset;
        break;
    case SEEK_END:
        pos = (loff_t)file->f_inode->i_size + offset;
        break;
    default:
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    if (pos < 0) {
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    file->f_pos = pos;
    mutex_unlock(&file->f_pos_lock);
    return pos;
}

static ssize_t pipe_read_inner(struct vfs_file *file, void *addr, size_t size,
                               bool allow_wait) {
    pipe_specific_t *spec = pipefs_spec_from_file(file);
    pipe_info_t *pipe;

    if (!spec || !spec->info)
        return -EINVAL;
    if (!spec->read)
        return -EBADF;
    pipe = spec->info;

    while (true) {
        spin_lock(&pipe->lock);

        if (pipe->ptr > 0) {
            size_t to_read = MIN(size, pipe->ptr);
            memcpy(addr, pipe->buf, to_read);
            memmove(pipe->buf, pipe->buf + to_read, pipe->ptr - to_read);
            pipe->ptr -= to_read;
            if (file && file->f_inode)
                file->f_inode->i_size = pipe->ptr;
            if (pipe->write_node)
                pipe->write_node->i_size = pipe->ptr;
            if (pipe->read_node)
                pipe->read_node->i_size = pipe->ptr;
            spin_unlock(&pipe->lock);

            if (pipe->write_node)
                vfs_poll_notify(pipe->write_node, EPOLLOUT);
            return (ssize_t)to_read;
        }

        if (pipe->write_fds == 0) {
            spin_unlock(&pipe->lock);
            return 0;
        }

        spin_unlock(&pipe->lock);

        if (!allow_wait)
            return 0;
        if (file->f_flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLHUP | EPOLLERR);
        vfs_poll_wait_arm(file->f_inode, &wait);
        int reason = vfs_poll_wait_sleep(file->f_inode, &wait, -1, "pipe_read");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK)
            return -EINTR;
    }
}

static ssize_t pipefs_read(struct vfs_file *file, void *buf, size_t count,
                           loff_t *ppos) {
    char *out = (char *)buf;
    size_t readn = 0;

    (void)ppos;
    if (!count)
        return 0;

    while (readn < count) {
        ssize_t ret =
            pipe_read_inner(file, out + readn, count - readn, readn == 0);
        if (ret < 0)
            return readn ? (ssize_t)readn : ret;
        if (ret == 0)
            break;
        readn += (size_t)ret;
    }

    return (ssize_t)readn;
}

static ssize_t pipe_write_inner(struct vfs_file *file, const void *addr,
                                size_t size, bool atomic, bool allow_wait) {
    pipe_specific_t *spec = pipefs_spec_from_file(file);
    pipe_info_t *pipe;

    if (!spec || !spec->info)
        return -EINVAL;
    if (!spec->write)
        return -EBADF;
    pipe = spec->info;

    while (true) {
        spin_lock(&pipe->lock);

        if (pipe->read_fds == 0) {
            spin_unlock(&pipe->lock);
            task_commit_signal(current_task, SIGPIPE, NULL);
            return -EPIPE;
        }

        size_t available = PIPE_BUFF - pipe->ptr;
        if (available > 0 && (!atomic || available >= size)) {
            size_t to_write = atomic ? size : MIN(size, available);
            memcpy(pipe->buf + pipe->ptr, addr, to_write);
            pipe->ptr += to_write;
            if (file && file->f_inode)
                file->f_inode->i_size = pipe->ptr;
            if (pipe->write_node)
                pipe->write_node->i_size = pipe->ptr;
            if (pipe->read_node)
                pipe->read_node->i_size = pipe->ptr;
            spin_unlock(&pipe->lock);

            if (pipe->read_node)
                vfs_poll_notify(pipe->read_node, EPOLLIN);
            return (ssize_t)to_write;
        }

        spin_unlock(&pipe->lock);

        if (!allow_wait)
            return 0;
        if (file->f_flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLOUT | EPOLLHUP | EPOLLERR);
        vfs_poll_wait_arm(file->f_inode, &wait);
        int reason =
            vfs_poll_wait_sleep(file->f_inode, &wait, -1, "pipe_write");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK)
            return -EINTR;
    }
}

static ssize_t pipefs_write(struct vfs_file *file, const void *buf,
                            size_t count, loff_t *ppos) {
    const char *data = (const char *)buf;
    size_t written = 0;
    bool atomic = (file->f_flags & O_NONBLOCK) && count <= PIPE_ATOMIC_MAX;

    (void)ppos;
    while (written < count) {
        ssize_t ret = pipe_write_inner(file, data + written, count - written,
                                       atomic, written == 0);
        if (ret < 0)
            return written ? (ssize_t)written : ret;
        if (ret == 0)
            break;
        written += (size_t)ret;
    }

    return (ssize_t)written;
}

static long pipefs_ioctl(struct vfs_file *file, unsigned long cmd,
                         unsigned long arg) {
    pipe_specific_t *spec = pipefs_spec_from_file(file);

    if (!spec || !spec->info)
        return -EINVAL;

    switch (cmd) {
    case FIONREAD:
        if (copy_to_user((void *)arg, &spec->info->ptr, sizeof(int)))
            return -EFAULT;
        return 0;
    default:
        return -EINVAL;
    }
}

static __poll_t pipefs_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    pipe_specific_t *spec = pipefs_spec_from_file(file);
    pipe_info_t *pipe;
    __poll_t out = 0;

    (void)pt;
    if (!spec || !spec->info)
        return EPOLLNVAL;
    pipe = spec->info;

    spin_lock(&pipe->lock);
    if (spec->read && pipe->write_fds == 0)
        out |= EPOLLHUP;
    if (spec->read && pipe->ptr > 0)
        out |= EPOLLIN | EPOLLRDNORM;

    if (spec->write && pipe->read_fds == 0)
        out |= EPOLLERR | EPOLLHUP;
    if (spec->write && pipe->read_fds > 0 && pipe->ptr < PIPE_BUFF)
        out |= EPOLLOUT | EPOLLWRNORM;
    spin_unlock(&pipe->lock);

    return out;
}

static int pipefs_open(struct vfs_inode *inode, struct vfs_file *file) {
    pipe_specific_t *spec = pipefs_spec_from_inode(inode);
    pipe_info_t *pipe;

    if (!inode || !file || !spec || !spec->info)
        return -EINVAL;

    pipe = spec->info;
    spin_lock(&pipe->lock);
    if (spec->write)
        pipe->write_fds++;
    if (spec->read)
        pipe->read_fds++;
    spin_unlock(&pipe->lock);

    file->f_op = inode->i_fop;
    file->private_data = spec;
    return 0;
}

static int pipefs_release(struct vfs_inode *inode, struct vfs_file *file) {
    pipe_specific_t *spec = pipefs_spec_from_file(file);
    pipe_info_t *pipe;
    uint32_t write_events = EPOLLHUP;
    bool free_spec = false;

    (void)inode;
    if (!spec || !spec->info)
        return 0;

    pipe = spec->info;
    spin_lock(&pipe->lock);
    if (spec->write) {
        if (pipe->write_fds > 0)
            pipe->write_fds--;
    }
    if (spec->read) {
        if (pipe->read_fds > 0)
            pipe->read_fds--;
    }

    if (pipe->read_node)
        vfs_poll_notify(pipe->read_node, EPOLLHUP);
    if (pipe->read_fds == 0)
        write_events |= EPOLLERR;
    if (pipe->write_node)
        vfs_poll_notify(pipe->write_node, write_events);
    spin_unlock(&pipe->lock);

    free_spec = file->private_data && file->private_data != inode->i_private;
    file->private_data = NULL;
    if (free_spec)
        free(spec);
    return 0;
}

static const struct vfs_file_operations pipefs_dir_file_ops = {
    .llseek = pipefs_llseek,
    .open = pipefs_open,
    .release = pipefs_release,
};

static const struct vfs_file_operations pipefs_file_ops = {
    .llseek = pipefs_llseek,
    .read = pipefs_read,
    .write = pipefs_write,
    .unlocked_ioctl = pipefs_ioctl,
    .poll = pipefs_poll,
    .open = pipefs_open,
    .release = pipefs_release,
};

static int pipefs_create_endpoint(struct vfs_file **out_file, pipe_info_t *pipe,
                                  bool write_end, unsigned int open_flags) {
    struct vfs_mount *mnt;
    struct vfs_super_block *sb;
    struct vfs_inode *inode;
    struct vfs_dentry *dentry;
    struct vfs_qstr name = {0};
    struct vfs_file *file;
    pipe_specific_t *spec;
    char namebuf[32];

    if (!out_file || !pipe)
        return -EINVAL;

    mnt = pipefs_get_internal_mount();
    if (!mnt)
        return -ENODEV;
    sb = mnt->mnt_sb;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    spec = calloc(1, sizeof(*spec));
    if (!spec) {
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    inode->i_ino = pipefs_next_ino(sb);
    inode->inode = inode->i_ino;
    inode->i_mode = S_IFIFO | 0600;
    inode->type = file_fifo;
    inode->i_nlink = 1;
    inode->i_fop = &pipefs_file_ops;
    inode->i_private = spec;

    spec->read = !write_end;
    spec->write = write_end;
    spec->info = pipe;

    snprintf(namebuf, sizeof(namebuf), "pipe-%llu-%c",
             (unsigned long long)inode->i_ino, write_end ? 'w' : 'r');
    vfs_qstr_make(&name, namebuf);
    dentry = vfs_d_alloc(sb, sb->s_root, &name);
    if (!dentry) {
        free(spec);
        inode->i_private = NULL;
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    vfs_d_instantiate(dentry, inode);
    file = vfs_alloc_file(&(struct vfs_path){.mnt = mnt, .dentry = dentry},
                          open_flags);
    if (!file) {
        vfs_dput(dentry);
        free(spec);
        inode->i_private = NULL;
        vfs_iput(inode);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    file->private_data = spec;
    if (write_end)
        pipe->write_node = inode;
    else
        pipe->read_node = inode;

    *out_file = file;
    vfs_dput(dentry);
    vfs_iput(inode);
    vfs_mntput(mnt);
    return 0;
}

void pipefs_init(void) {
    mutex_init(&pipefs_mount_lock);
    vfs_register_filesystem(&pipefs_fs_type);
}

ssize_t pipefs_named_read(struct vfs_file *file, void *buf, size_t count,
                          loff_t *ppos) {
    return pipefs_read(file, buf, count, ppos);
}

ssize_t pipefs_named_write(struct vfs_file *file, const void *buf, size_t count,
                           loff_t *ppos) {
    return pipefs_write(file, buf, count, ppos);
}

__poll_t pipefs_named_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    return pipefs_poll(file, pt);
}

int pipefs_named_open(struct vfs_inode *inode, struct vfs_file *file) {
    pipe_info_t *pipe;
    pipe_specific_t *spec;
    unsigned int accmode;

    if (!inode || !file || !S_ISFIFO(inode->i_mode))
        return -EINVAL;

    pipe = pipefs_named_ensure_info(inode);
    if (!pipe)
        return -ENOMEM;

    accmode = file->f_flags & O_ACCMODE_FLAGS;
    spec = calloc(1, sizeof(*spec));
    if (!spec)
        return -ENOMEM;

    spec->read = accmode != O_WRONLY;
    spec->write = accmode != O_RDONLY;
    spec->info = pipe;

    spin_lock(&pipe->lock);
    if (spec->read)
        pipe->read_fds++;
    if (spec->write)
        pipe->write_fds++;
    pipe->read_node = inode;
    pipe->write_node = inode;
    spin_unlock(&pipe->lock);

    file->private_data = spec;
    return 0;
}

int pipefs_named_release(struct vfs_inode *inode, struct vfs_file *file) {
    return pipefs_release(inode, file);
}

void pipefs_named_evict_inode(struct vfs_inode *inode) {
    pipe_info_t *pipe;

    if (!inode || !S_ISFIFO(inode->i_mode))
        return;

    pipe = pipefs_named_info(inode);
    if (!pipe)
        return;

    pipe->read_node = NULL;
    pipe->write_node = NULL;
    free(pipe->buf);
    free(pipe);
    inode->i_private = NULL;
}

uint64_t sys_pipe(int pipefd[2], uint64_t flags) {
    struct vfs_file *read_file = NULL;
    struct vfs_file *write_file = NULL;
    pipe_info_t *info;
    int i1, i2;
    int ret;

    if (!pipefd)
        return -EFAULT;

    info = pipefs_alloc_info();
    if (!info)
        return -ENOMEM;

    ret = pipefs_create_endpoint(&read_file, info, false,
                                 O_RDONLY | (flags & O_NONBLOCK));
    if (ret < 0)
        goto out_free_pipe;

    ret = pipefs_create_endpoint(&write_file, info, true,
                                 O_WRONLY | (flags & O_NONBLOCK));
    if (ret < 0)
        goto out_close_read;

    i1 = task_install_file(current_task, read_file,
                           (flags & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    if (i1 < 0) {
        ret = i1;
        goto out_close_both;
    }

    i2 = task_install_file(current_task, write_file,
                           (flags & O_CLOEXEC) ? FD_CLOEXEC : 0, i1 + 1);
    if (i2 < 0) {
        task_close_file_descriptor(current_task, i1);
        ret = i2;
        goto out_close_both;
    }

    vfs_close_file(read_file);
    vfs_close_file(write_file);

    int kpipefd[2] = {i1, i2};
    if (copy_to_user(pipefd, kpipefd, sizeof(kpipefd))) {
        task_close_file_descriptor(current_task, i1);
        task_close_file_descriptor(current_task, i2);
        return -EFAULT;
    }

    info->read_fds++;
    info->write_fds++;

    return 0;

out_close_both:
    if (write_file)
        vfs_close_file(write_file);
out_close_read:
    if (read_file)
        vfs_close_file(read_file);
    return ret;

out_free_pipe:
    free(info->buf);
    free(info);
    return ret;
}
