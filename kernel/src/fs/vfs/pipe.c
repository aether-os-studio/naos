#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/proc.h>
#include <drivers/fb.h>

vfs_node_t pipefs_root;
int pipefs_id = 0;
static int pipefd_id = 0;

void pipefs_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)parent;
    (void)name;
}

ssize_t pipefs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if (size > PIPE_BUFF)
        size = PIPE_BUFF;

    void *file = fd->node->handle;

    pipe_specific_t *spec = (pipe_specific_t *)file;
    if (!spec)
        return -EINVAL;
    pipe_info_t *pipe = spec->info;
    if (!pipe)
        return -EINVAL;

    if (!size)
        return 0;

    while (true) {
        spin_lock(&pipe->lock);

        if (pipe->ptr > 0) {
            // 实际读取量
            uint32_t to_read = MIN(size, pipe->ptr);
            memcpy(addr, pipe->buf, to_read);
            memmove(pipe->buf, &pipe->buf[to_read], pipe->ptr - to_read);
            pipe->ptr -= to_read;
            spin_unlock(&pipe->lock);
            if (pipe->write_node)
                vfs_poll_notify(pipe->write_node, EPOLLOUT);
            return to_read;
        }

        if (pipe->write_fds == 0) {
            spin_unlock(&pipe->lock);
            return 0;
        }

        spin_unlock(&pipe->lock);

        if (fd->flags & O_NONBLOCK) {
            return -EWOULDBLOCK;
        }

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLHUP | EPOLLERR);
        vfs_poll_wait_arm(fd->node, &wait);
        int reason = task_block(current_task, TASK_BLOCKING, -1, "pipe_read");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK)
            return -EINTR;
    }
}

ssize_t pipe_write_inner(fd_t *fd, void *file, const void *addr, size_t size) {
    pipe_specific_t *spec = (pipe_specific_t *)file;
    pipe_info_t *pipe = spec->info;

    while (true) {
        spin_lock(&pipe->lock);

        if (pipe->read_fds == 0) {
            spin_unlock(&pipe->lock);
            return -EPIPE;
        }

        if ((PIPE_BUFF - pipe->ptr) >= size) {
            memcpy(&pipe->buf[pipe->ptr], addr, size);
            pipe->ptr += size;
            spin_unlock(&pipe->lock);
            if (pipe->read_node)
                vfs_poll_notify(pipe->read_node, EPOLLIN);
            return size;
        }

        spin_unlock(&pipe->lock);

        if (fd->flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLOUT | EPOLLHUP | EPOLLERR);
        vfs_poll_wait_arm(fd->node, &wait);
        int reason = task_block(current_task, TASK_BLOCKING, -1, "pipe_write");
        vfs_poll_wait_disarm(&wait);
        if (reason != EOK)
            return -EINTR;
    }
}

ssize_t pipefs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    int ret = 0;
    void *file = fd->node->handle;
    const char *data = addr;
    size_t chunks = size / PIPE_BUFF;
    size_t remainder = size % PIPE_BUFF;
    if (chunks)
        for (size_t i = 0; i < chunks; i++) {
            int cycle = 0;
            while (cycle < PIPE_BUFF) {
                ssize_t wrote = pipe_write_inner(
                    fd, file, data + i * PIPE_BUFF + cycle, PIPE_BUFF - cycle);
                if (wrote < 0)
                    return wrote;
                cycle += wrote;
            }
            ret += cycle;
        }

    if (remainder) {
        size_t cycle = 0;
        while (cycle < remainder) {
            ssize_t wrote = pipe_write_inner(
                fd, file, data + chunks * PIPE_BUFF + cycle, remainder - cycle);
            if (wrote < 0)
                return wrote;
            cycle += wrote;
        }
        ret += cycle;
    }

    return ret;
}

int pipefs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    switch (cmd) {
    default:
        return -EINVAL;
    }
}

bool pipefs_close(vfs_node_t node) {
    pipe_specific_t *spec = node ? node->handle : NULL;
    if (!spec)
        return true;
    pipe_info_t *pipe = spec->info;

    spin_lock(&pipe->lock);
    if (spec->write) {
        pipe->write_fds--;
    } else {
        pipe->read_fds--;
    }

    llist_delete(&spec->node->node_for_childs);

    if (spec->write && pipe->write_fds == 0)
        free(spec);
    else if (!spec->write && pipe->read_fds == 0)
        free(spec);

    if (pipe->read_node)
        vfs_poll_notify(pipe->read_node, EPOLLHUP);
    if (pipe->write_node)
        vfs_poll_notify(pipe->write_node, EPOLLHUP);

    if (pipe->write_fds == 0 && pipe->read_fds == 0) {
        spin_unlock(&pipe->lock);
        free_frames_bytes(pipe->buf, PIPE_BUFF);
        free(pipe);
        return true;
    }

    spin_unlock(&pipe->lock);

    return true;
}

int pipefs_poll(vfs_node_t node, size_t events) {
    pipe_specific_t *spec = node ? node->handle : NULL;
    if (!spec)
        return EPOLLNVAL;
    pipe_info_t *pipe = spec->info;

    int out = 0;

    spin_lock(&pipe->lock);
    if (events & EPOLLIN) {
        if (!pipe->write_fds)
            out |= EPOLLHUP;
        if (pipe->ptr > 0)
            out |= EPOLLIN;
    }

    if (events & EPOLLOUT) {
        if (!pipe->read_fds)
            out |= EPOLLHUP;
        if (pipe->ptr < PIPE_BUFF)
            out |= EPOLLOUT;
    }
    spin_unlock(&pipe->lock);
    return out;
}

int pipefs_stat(vfs_node_t node) {
    pipe_specific_t *spec = node ? node->handle : NULL;
    if (!spec)
        return -EINVAL;
    pipe_info_t *pipe = spec->info;

    if (!pipe)
        return 0;

    node->size = pipe->ptr;

    return 0;
}

static vfs_operations_t callbacks = {
    .open = (vfs_open_t)pipefs_open,
    .close = (vfs_close_t)pipefs_close,
    .read = pipefs_read,
    .write = pipefs_write,
    .stat = (vfs_stat_t)pipefs_stat,
    .ioctl = (vfs_ioctl_t)pipefs_ioctl,
    .poll = pipefs_poll,

    .free_handle = vfs_generic_free_handle,
};

fs_t pipefs = {
    .name = "pipefs",
    .magic = 0,
    .ops = &callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void pipefs_init() {
    pipefs_id = vfs_regist(&pipefs);
    pipefs_root = vfs_node_alloc(NULL, "pipe");
    pipefs_root->type = file_dir;
    pipefs_root->mode = 0644;
    pipefs_root->fsid = pipefs_id;
}

uint64_t sys_pipe(int pipefd[2], uint64_t flags) {
    if (!pipefd) {
        return -EFAULT;
    }

    char buf[16];
    sprintf(buf, "pipe%d", pipefd_id++);

    vfs_node_t node_input = vfs_node_alloc(pipefs_root, buf);
    node_input->type = file_pipe;
    node_input->fsid = pipefs_id;
    node_input->refcount++;
    pipefs_root->mode = 0700;

    sprintf(buf, "pipe%d", pipefd_id++);
    vfs_node_t node_output = vfs_node_alloc(pipefs_root, buf);
    node_output->type = file_pipe;
    node_output->fsid = pipefs_id;
    node_output->refcount++;
    pipefs_root->mode = 0700;

    pipe_info_t *info = (pipe_info_t *)malloc(sizeof(pipe_info_t));
    memset(info, 0, sizeof(pipe_info_t));
    info->buf = alloc_frames_bytes(PIPE_BUFF);
    memset(info->buf, 0, PIPE_BUFF);
    info->read_fds = 1;
    info->write_fds = 1;
    info->read_node = node_input;
    info->write_node = node_output;
    info->lock.lock = 0;
    info->ptr = 0;

    pipe_specific_t *read_spec =
        (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    read_spec->write = false;
    read_spec->info = info;
    read_spec->node = node_input;

    pipe_specific_t *write_spec =
        (pipe_specific_t *)malloc(sizeof(pipe_specific_t));
    write_spec->write = true;
    write_spec->info = info;
    write_spec->node = node_output;

    node_input->handle = read_spec;
    node_output->handle = write_spec;

    int i1 = -1, i2 = -1;
    int ret = -EMFILE;

    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (current_task->fd_info->fds[i] == NULL) {
                if (i1 == -1)
                    i1 = i;
                else {
                    i2 = i;
                    break;
                }
            }
        }

        if (i1 < 0 || i2 < 0)
            break;

        fd_t *fd_read = malloc(sizeof(fd_t));
        fd_t *fd_write = malloc(sizeof(fd_t));
        if (!fd_read || !fd_write) {
            free(fd_read);
            free(fd_write);
            ret = -ENOMEM;
            i1 = i2 = -1;
            break;
        }

        memset(fd_read, 0, sizeof(fd_t));
        memset(fd_write, 0, sizeof(fd_t));
        fd_read->node = node_input;
        fd_read->offset = 0;
        fd_read->flags = flags;
        fd_read->close_on_exec = !!(flags & O_CLOEXEC);
        fd_write->node = node_output;
        fd_write->offset = 0;
        fd_write->flags = flags;
        fd_write->close_on_exec = !!(flags & O_CLOEXEC);

        current_task->fd_info->fds[i1] = fd_read;
        current_task->fd_info->fds[i2] = fd_write;
        procfs_on_open_file(current_task, i1);
        procfs_on_open_file(current_task, i2);
        ret = 0;
    });

    if (ret < 0) {
        free_frames_bytes(info->buf, PIPE_BUFF);
        free(info);
        vfs_free(node_input);
        vfs_free(node_output);
        return ret;
    }

    int kpipefd[2] = {i1, i2};
    if (copy_to_user(pipefd, kpipefd, sizeof(kpipefd))) {
        sys_close(i1);
        sys_close(i2);
        return -EFAULT;
    }

    return 0;
}
