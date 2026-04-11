#include <drivers/pty.h>
#include <task/task.h>
#include <fs/vfs/vfs.h>
#include <init/callbacks.h>

uint8_t *pty_bitmap = 0;
spinlock_t pty_global_lock = SPIN_INIT;
pty_pair_t first_pair;

ssize_t pts_write_inner(fd_t *fd, uint8_t *in, size_t limit);
extern void send_process_group_signal(int pgid, int sig);

static const struct vfs_file_operations ptmx_file_ops;
static const struct vfs_file_operations pts_file_ops;
int pts_ioctl(pty_pair_t *pair, uint64_t request, void *arg);

static inline pty_pair_t *pty_pair_from_file(fd_t *file) {
    if (!file)
        return NULL;
    if (file->private_data)
        return (pty_pair_t *)file->private_data;
    if (!file->f_inode)
        return NULL;
    return (pty_pair_t *)file->f_inode->i_private;
}

static vfs_node_t *pty_lookup_inode_path(const char *path) {
    struct vfs_path p = {0};
    vfs_node_t *inode = NULL;

    if (!path)
        return NULL;
    if (vfs_filename_lookup(AT_FDCWD, path, LOOKUP_FOLLOW, &p) < 0)
        return NULL;
    if (p.dentry && p.dentry->d_inode)
        inode = vfs_igrab(p.dentry->d_inode);
    vfs_path_put(&p);
    return inode;
}

static inline void pty_notify_node(vfs_node_t *node, uint32_t events) {
    if (node && events)
        vfs_poll_notify(node, events);
}

static inline void pty_notify_pair_master(pty_pair_t *pair, uint32_t events) {
    if (pair)
        pty_notify_node(pair->ptmx_node, events);
}

static inline void pty_notify_pair_slave(pty_pair_t *pair, uint32_t events) {
    if (pair)
        pty_notify_node(pair->pts_node, events);
}

static int pty_wait_node(vfs_node_t *node, uint32_t events,
                         const char *reason) {
    if (!node || !current_task)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    int polled = vfs_poll(node, want);
    if (polled < 0)
        return polled;
    if (polled & (int)want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(node, &wait) < 0)
        return -EINVAL;
    int ret = vfs_poll_wait_sleep(node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
}

static int pty_tcxonc_locked(pty_pair_t *pair, bool from_master, uintptr_t arg,
                             uint32_t *notify_master, uint32_t *notify_slave) {
    if (!pair)
        return -EINVAL;

    int action = (int)arg;
    switch (action) {
    case TCOOFF:
        if (from_master)
            pair->stop_master_output = true;
        else
            pair->stop_slave_output = true;
        return 0;
    case TCOON:
        if (from_master) {
            pair->stop_master_output = false;
            if (notify_master)
                *notify_master |= EPOLLOUT;
        } else {
            pair->stop_slave_output = false;
            if (notify_slave)
                *notify_slave |= EPOLLOUT;
        }
        return 0;
    case TCIOFF:
    case TCION: {
        uint8_t flow_char = pair->term.c_cc[action == TCIOFF ? VSTOP : VSTART];
        if (from_master) {
            if (!pair->slaveFds || pair->ptrSlave >= PTY_BUFF_SIZE)
                return pair->slaveFds ? -EAGAIN : 0;
            pair->bufferSlave[pair->ptrSlave++] = flow_char;
            if (notify_slave)
                *notify_slave |= EPOLLIN;
        } else {
            if (!pair->masterFds || pair->ptrMaster >= PTY_BUFF_SIZE)
                return pair->masterFds ? -EAGAIN : 0;
            pair->bufferMaster[pair->ptrMaster++] = flow_char;
            if (notify_master)
                *notify_master |= EPOLLIN;
        }
        return 0;
    }
    default:
        return -EINVAL;
    }
}

int pty_bitmap_decide() {
    int ret = -1;
    spin_lock(&pty_global_lock);
    for (int i = 0; i < PTY_MAX; i++) {
        if (!(pty_bitmap[i / 8] & (1 << (i % 8)))) {
            pty_bitmap[i / 8] |= (1 << (i % 8));
            ret = i;
            break;
        }
    }
    spin_unlock(&pty_global_lock);
    return ret;
}

void pty_bitmap_remove(int index) {
    spin_lock(&pty_global_lock);
    pty_bitmap[index / 8] &= ~(1 << (index % 8));
    spin_unlock(&pty_global_lock);
}

void pty_termios_default(struct termios *term) {
    term->c_iflag = ICRNL | IXON | BRKINT | ISTRIP | INPCK;
    term->c_oflag = OPOST | ONLCR;
    term->c_cflag = B38400 | CS8 | CREAD | HUPCL;
    term->c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK;
    term->c_cc[VINTR] = 3;
    term->c_cc[VQUIT] = 28;
    term->c_cc[VERASE] = 127;
    term->c_cc[VKILL] = 21;
    term->c_cc[VEOF] = 4;
    term->c_cc[VTIME] = 0;
    term->c_cc[VMIN] = 1;
    term->c_cc[VSTART] = 17;
    term->c_cc[VSTOP] = 19;
    term->c_cc[VSUSP] = 26;
}

static int pty_pair_install_slave_node(pty_pair_t *pair) {
    char path[32];
    vfs_node_t *inode;

    if (!pair)
        return -EINVAL;

    snprintf(path, sizeof(path), "/dev/pts/%d", pair->id);
    (void)vfs_mknodat(AT_FDCWD, path, S_IFCHR | 0620, (136U << 8) | pair->id);
    inode = pty_lookup_inode_path(path);
    if (!inode)
        return -ENOENT;

    inode->i_fop = &pts_file_ops;
    inode->type = file_stream;
    inode->i_private = pair;

    if (pair->pts_node)
        vfs_iput(pair->pts_node);
    pair->pts_node = inode;
    return 0;
}

static void pty_pair_cleanup(pty_pair_t *pair) {
    char path[32];

    if (!pair)
        return;

    free(pair->bufferMaster);
    free(pair->bufferSlave);
    if (pair->pts_node)
        vfs_iput(pair->pts_node);
    pair->pts_node = NULL;
    pair->ptmx_node = NULL;

    snprintf(path, sizeof(path), "/dev/pts/%d", pair->id);
    (void)vfs_unlinkat(AT_FDCWD, path, 0);
    pty_bitmap_remove(pair->id);

    spin_lock(&pty_global_lock);
    pty_pair_t *n = &first_pair;
    while (n->next && n->next != pair)
        n = n->next;
    if (n->next)
        n->next = pair->next;
    spin_unlock(&pty_global_lock);

    free(pair);
}

static void pts_ctrl_assign(pty_pair_t *pair) {
    pair->ctrlSession = current_task->sid;
    pair->ctrlPgid = current_task->pgid;
}

static int pty_open_peer_fd(pty_pair_t *pair, uint64_t flags) {
    static const uint64_t allowed_flags =
        O_ACCMODE_FLAGS | O_NOCTTY | O_NONBLOCK | O_CLOEXEC;
    char path[32];
    struct vfs_file *file = NULL;
    struct vfs_open_how how = {0};
    int ret;

    if (!pair || !current_task || !current_task->fd_info)
        return -EINVAL;
    if (flags & ~allowed_flags)
        return -EINVAL;

    mutex_lock(&pair->lock);
    if (pair->locked) {
        mutex_unlock(&pair->lock);
        return -EIO;
    }
    mutex_unlock(&pair->lock);

    snprintf(path, sizeof(path), "/dev/pts/%d", pair->id);
    how.flags = O_RDWR | (flags & O_NONBLOCK);
    ret = vfs_openat(AT_FDCWD, path, &how, &file);
    if (ret < 0)
        return ret;

    ret = task_install_file(current_task, file,
                            (flags & O_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(file);
    return ret;
}

void pty_init() {
    if (pty_bitmap)
        return;
    pty_bitmap = calloc(PTY_MAX / 8, 1);
    first_pair.id = 0xffffffff;
}

static int ptmx_open_file(struct vfs_inode *inode, struct vfs_file *file) {
    int id;
    pty_pair_t *pair;

    if (!inode || !file)
        return -EINVAL;

    id = pty_bitmap_decide();
    if (id < 0)
        return -ENOSPC;

    pair = calloc(1, sizeof(*pair));
    if (!pair) {
        pty_bitmap_remove(id);
        return -ENOMEM;
    }

    mutex_init(&pair->lock);
    pair->id = id;
    pair->bufferMaster = malloc(PTY_BUFF_SIZE);
    pair->bufferSlave = malloc(PTY_BUFF_SIZE);
    if (!pair->bufferMaster || !pair->bufferSlave) {
        free(pair->bufferMaster);
        free(pair->bufferSlave);
        free(pair);
        pty_bitmap_remove(id);
        return -ENOMEM;
    }

    pty_termios_default(&pair->term);
    pair->win.ws_row = 24;
    pair->win.ws_col = 80;
    pair->tty_kbmode = K_XLATE;
    pair->masterFds = 1;
    pair->ptmx_node = inode;

    spin_lock(&pty_global_lock);
    pty_pair_t *n = &first_pair;
    while (n->next)
        n = n->next;
    n->next = pair;
    spin_unlock(&pty_global_lock);

    if (pty_pair_install_slave_node(pair) < 0) {
        pty_pair_cleanup(pair);
        return -EIO;
    }

    file->private_data = pair;
    return 0;
}

static int ptmx_release_file(struct vfs_inode *inode, struct vfs_file *file) {
    pty_pair_t *pair = pty_pair_from_file(file);

    (void)inode;
    if (!pair)
        return 0;

    mutex_lock(&pair->lock);
    if (pair->masterFds > 0)
        pair->masterFds--;
    mutex_unlock(&pair->lock);

    pty_notify_pair_slave(pair, EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (!pair->masterFds && !pair->slaveFds)
        pty_pair_cleanup(pair);
    file->private_data = NULL;
    return 0;
}

static size_t ptmx_data_avail(pty_pair_t *pair) { return pair->ptrMaster; }

static ssize_t ptmx_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    pty_pair_t *pair = pty_pair_from_file(fd);
    (void)offset;
    if (!pair)
        return -EINVAL;

    while (true) {
        mutex_lock(&pair->lock);
        if (ptmx_data_avail(pair) > 0) {
            size_t to_copy = MIN(size, ptmx_data_avail(pair));
            memcpy(addr, pair->bufferMaster, to_copy);
            size_t remaining = pair->ptrMaster - to_copy;
            if (remaining > 0)
                memmove(pair->bufferMaster, &pair->bufferMaster[to_copy],
                        remaining);
            pair->ptrMaster -= to_copy;
            mutex_unlock(&pair->lock);
            pty_notify_pair_slave(pair, EPOLLOUT);
            return (ssize_t)to_copy;
        }
        bool no_slave = (pair->slaveFds == 0);
        mutex_unlock(&pair->lock);
        if (no_slave)
            return 0;
        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;
        int reason = pty_wait_node(pair->ptmx_node ? pair->ptmx_node : fd->node,
                                   EPOLLIN, "ptmx_read");
        if (reason != EOK)
            return -EINTR;
    }
}

static ssize_t ptmx_write(fd_t *fd, const void *addr, size_t offset,
                          size_t limit) {
    pty_pair_t *pair = pty_pair_from_file(fd);
    (void)offset;
    if (!pair)
        return -EINVAL;

    while (true) {
        mutex_lock(&pair->lock);
        if (pair->stop_master_output) {
            mutex_unlock(&pair->lock);
            if (fd_get_flags(fd) & O_NONBLOCK)
                return -EWOULDBLOCK;
            int reason =
                pty_wait_node(pair->ptmx_node ? pair->ptmx_node : fd->node,
                              EPOLLOUT, "ptmx_tcooff");
            if (reason != EOK)
                return -EINTR;
            continue;
        }
        if (!pair->slaveFds) {
            mutex_unlock(&pair->lock);
            return -EIO;
        }
        if (pair->ptrSlave < PTY_BUFF_SIZE) {
            const uint8_t *in = addr;
            size_t written = 0, echoed = 0, echo_start = pair->ptrSlave;
            for (size_t i = 0; i < limit; i++) {
                uint8_t ch = in[i];
                if (pair->term.c_lflag & ISIG) {
                    uint64_t pgid = pair->frontProcessGroup
                                        ? pair->frontProcessGroup
                                        : pair->ctrlPgid;
                    if (pgid) {
                        if (ch == pair->term.c_cc[VINTR]) {
                            send_process_group_signal(pgid, SIGINT);
                            written++;
                            continue;
                        }
                        if (ch == pair->term.c_cc[VQUIT]) {
                            send_process_group_signal(pgid, SIGQUIT);
                            written++;
                            continue;
                        }
                        if (ch == pair->term.c_cc[VSUSP]) {
                            send_process_group_signal(pgid, SIGTSTP);
                            written++;
                            continue;
                        }
                    }
                }
                if ((pair->term.c_iflag & ICRNL) && ch == '\r')
                    ch = '\n';
                if (pair->ptrSlave + 1 > PTY_BUFF_SIZE)
                    break;
                pair->bufferSlave[pair->ptrSlave++] = ch;
                echoed++;
                written++;
            }
            mutex_unlock(&pair->lock);
            if (written > 0)
                pty_notify_pair_slave(pair, EPOLLIN);
            if ((pair->term.c_lflag & ICANON) && (pair->term.c_lflag & ECHO) &&
                echoed > 0)
                pts_write_inner(fd, &pair->bufferSlave[echo_start], echoed);
            return (ssize_t)written;
        }
        mutex_unlock(&pair->lock);
        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;
        int reason = pty_wait_node(pair->ptmx_node ? pair->ptmx_node : fd->node,
                                   EPOLLOUT, "ptmx_write");
        if (reason != EOK)
            return -EINTR;
    }
}

static long ptmx_ioctl(fd_t *fd, unsigned long request, unsigned long arg) {
    pty_pair_t *pair = pty_pair_from_file(fd);
    int ret = -ENOTTY;
    uint32_t notify_master = 0, notify_slave = 0;
    size_t number = _IOC_NR(request);

    if (!pair)
        return -EINVAL;
    if ((request & 0xffffffffUL) == TIOCGPTPEER)
        return pty_open_peer_fd(pair, (uint64_t)arg);

    mutex_lock(&pair->lock);
    switch (number) {
    case 0x31: {
        int lock = 0;
        if (!arg || copy_from_user(&lock, (const void *)arg, sizeof(lock)))
            ret = -EFAULT;
        else {
            pair->locked = lock != 0;
            ret = 0;
        }
        break;
    }
    case 0x30:
        ret = (!arg || copy_to_user((void *)arg, &pair->id, sizeof(int)))
                  ? -EFAULT
                  : 0;
        break;
    }

    if (ret == -ENOTTY) {
        switch (request & 0xffffffffU) {
        case TIOCGWINSZ:
            ret = (!arg || copy_to_user((void *)arg, &pair->win,
                                        sizeof(struct winsize)))
                      ? -EFAULT
                      : 0;
            break;
        case TIOCSWINSZ:
            ret = (!arg || copy_from_user(&pair->win, (const void *)arg,
                                          sizeof(struct winsize)))
                      ? -EFAULT
                      : 0;
            break;
        case TIOCSCTTY:
            pts_ctrl_assign(pair);
            ret = 0;
            break;
        case TCGETS:
            ret = (!arg ||
                   copy_to_user((void *)arg, &pair->term, sizeof(termios)))
                      ? -EFAULT
                      : 0;
            break;
        case TCSETS:
        case TCSETSW:
        case TCSETSF:
            ret = (!arg || copy_from_user(&pair->term, (const void *)arg,
                                          sizeof(termios)))
                      ? -EFAULT
                      : 0;
            break;
        case TCXONC:
            ret = pty_tcxonc_locked(pair, false, arg, &notify_master,
                                    &notify_slave);
            break;
        case TIOCGPGRP:
            ret =
                copy_to_user((void *)arg, &pair->frontProcessGroup, sizeof(int))
                    ? -EFAULT
                    : 0;
            break;
        case TIOCSPGRP:
            ret = copy_from_user(&pair->frontProcessGroup, (const void *)arg,
                                 sizeof(int))
                      ? -EFAULT
                      : 0;
            break;
        case TIOCNOTTY:
        case VT_ACTIVATE:
        case VT_WAITACTIVE:
            ret = 0;
            break;
        default:
            ret = pts_ioctl(pair, request, (void *)arg);
            break;
        }
    }
    mutex_unlock(&pair->lock);

    if (ret >= 0) {
        pty_notify_pair_master(pair, notify_master);
        pty_notify_pair_slave(pair, notify_slave);
    }
    return ret;
}

static __poll_t ptmx_poll(fd_t *file, struct vfs_poll_table *pt) {
    pty_pair_t *pair = pty_pair_from_file(file);
    int revents = 0;
    (void)pt;
    if (!pair)
        return EPOLLNVAL;

    mutex_lock(&pair->lock);
    if (ptmx_data_avail(pair) > 0)
        revents |= EPOLLIN;
    if (pair->ptrSlave < PTY_BUFF_SIZE)
        revents |= EPOLLOUT;
    if (!pair->slaveFds)
        revents |= EPOLLHUP | EPOLLRDHUP;
    mutex_unlock(&pair->lock);
    return revents;
}

static int pts_open_file(struct vfs_inode *inode, struct vfs_file *file) {
    pty_pair_t *pair = inode ? (pty_pair_t *)inode->i_private : NULL;

    if (!pair || !file)
        return -EINVAL;
    mutex_lock(&pair->lock);
    if (pair->locked) {
        mutex_unlock(&pair->lock);
        return -EIO;
    }
    pair->slaveFds++;
    file->private_data = pair;
    mutex_unlock(&pair->lock);
    return 0;
}

static int pts_release_file(struct vfs_inode *inode, struct vfs_file *file) {
    pty_pair_t *pair = pty_pair_from_file(file);
    (void)inode;
    if (!pair)
        return 0;

    mutex_lock(&pair->lock);
    if (pair->slaveFds > 0)
        pair->slaveFds--;
    mutex_unlock(&pair->lock);

    pty_notify_pair_master(pair, EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (!pair->masterFds && !pair->slaveFds)
        pty_pair_cleanup(pair);
    file->private_data = NULL;
    return 0;
}

static size_t pts_data_avail(pty_pair_t *pair) {
    if (!(pair->term.c_lflag & ICANON))
        return pair->ptrSlave;
    for (size_t i = 0; i < (size_t)pair->ptrSlave; i++) {
        if (pair->bufferSlave[i] == '\n' ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOF] ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOL] ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOL2])
            return i + 1;
    }
    return 0;
}

static ssize_t pts_read(fd_t *fd, void *out, size_t offset, size_t limit) {
    pty_pair_t *pair = pty_pair_from_file(fd);
    (void)offset;
    if (!pair)
        return -EINVAL;

    while (true) {
        mutex_lock(&pair->lock);
        if (pts_data_avail(pair) > 0) {
            size_t to_copy = MIN(limit, pts_data_avail(pair));
            memcpy(out, pair->bufferSlave, to_copy);
            size_t remaining = pair->ptrSlave - to_copy;
            if (remaining > 0)
                memmove(pair->bufferSlave, &pair->bufferSlave[to_copy],
                        remaining);
            pair->ptrSlave -= to_copy;
            mutex_unlock(&pair->lock);
            pty_notify_pair_master(pair, EPOLLOUT);
            return (ssize_t)to_copy;
        }
        bool no_master = (pair->masterFds == 0);
        mutex_unlock(&pair->lock);
        if (no_master)
            return 0;
        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;
        int reason = pty_wait_node(pair->pts_node ? pair->pts_node : fd->node,
                                   EPOLLIN, "pts_read");
        if (reason != EOK)
            return -EINTR;
    }
}

ssize_t pts_write_inner(fd_t *fd, uint8_t *in, size_t limit) {
    pty_pair_t *pair = pty_pair_from_file(fd);
    if (!pair)
        return -EINVAL;

    while (true) {
        mutex_lock(&pair->lock);
        if (pair->stop_slave_output) {
            mutex_unlock(&pair->lock);
            if (fd_get_flags(fd) & O_NONBLOCK)
                return -EWOULDBLOCK;
            int reason =
                pty_wait_node(pair->pts_node ? pair->pts_node : fd->node,
                              EPOLLOUT, "pts_tcooff");
            if (reason != EOK)
                return -EINTR;
            continue;
        }
        if (!pair->masterFds) {
            mutex_unlock(&pair->lock);
            return -EIO;
        }
        if (pair->ptrMaster < PTY_BUFF_SIZE) {
            size_t written = 0;
            bool translate =
                (pair->term.c_oflag & OPOST) && (pair->term.c_oflag & ONLCR);
            for (size_t i = 0; i < limit; i++) {
                uint8_t ch = in[i];
                if (translate && ch == '\n') {
                    if (pair->ptrMaster + 2 > PTY_BUFF_SIZE)
                        break;
                    pair->bufferMaster[pair->ptrMaster++] = '\r';
                    pair->bufferMaster[pair->ptrMaster++] = '\n';
                } else {
                    if (pair->ptrMaster + 1 > PTY_BUFF_SIZE)
                        break;
                    pair->bufferMaster[pair->ptrMaster++] = ch;
                }
                written++;
            }
            mutex_unlock(&pair->lock);
            if (written > 0)
                pty_notify_pair_master(pair, EPOLLIN);
            return (ssize_t)written;
        }
        mutex_unlock(&pair->lock);
        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;
        int reason = pty_wait_node(pair->pts_node ? pair->pts_node : fd->node,
                                   EPOLLOUT, "pts_write");
        if (reason != EOK)
            return -EINTR;
    }
}

static ssize_t pts_write(fd_t *fd, const void *in, size_t offset,
                         size_t limit) {
    ssize_t ret = 0;
    (void)offset;
    size_t chunks = limit / PTY_BUFF_SIZE;
    size_t remainder = limit % PTY_BUFF_SIZE;
    const uint8_t *buf = in;

    for (size_t i = 0; i < chunks; i++) {
        size_t cycle = 0;
        while (cycle < PTY_BUFF_SIZE) {
            ssize_t r =
                pts_write_inner(fd, (uint8_t *)buf + i * PTY_BUFF_SIZE + cycle,
                                PTY_BUFF_SIZE - cycle);
            if (r < 0)
                return ret ? ret : r;
            cycle += (size_t)r;
        }
        ret += (ssize_t)cycle;
    }

    if (remainder) {
        size_t cycle = 0;
        while (cycle < remainder) {
            ssize_t r = pts_write_inner(
                fd, (uint8_t *)buf + chunks * PTY_BUFF_SIZE + cycle,
                remainder - cycle);
            if (r < 0)
                return ret ? ret : r;
            cycle += (size_t)r;
        }
        ret += (ssize_t)cycle;
    }
    return ret;
}

int pts_ioctl(pty_pair_t *pair, uint64_t request, void *arg) {
    int ret = -ENOTTY;
    uint32_t notify_master = 0, notify_slave = 0;

    if (!pair)
        return -EINVAL;

    mutex_lock(&pair->lock);
    switch (request) {
    case TIOCGWINSZ:
        ret = (!arg || copy_to_user(arg, &pair->win, sizeof(struct winsize)))
                  ? -EFAULT
                  : 0;
        break;
    case TIOCSWINSZ:
        ret = (!arg || copy_from_user(&pair->win, arg, sizeof(struct winsize)))
                  ? -EFAULT
                  : 0;
        break;
    case TIOCSCTTY:
        pts_ctrl_assign(pair);
        ret = 0;
        break;
    case TCGETS:
        ret = (!arg || copy_to_user(arg, &pair->term, sizeof(termios)))
                  ? -EFAULT
                  : 0;
        break;
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
        ret = (!arg || copy_from_user(&pair->term, arg, sizeof(termios)))
                  ? -EFAULT
                  : 0;
        break;
    case TCXONC:
        ret = pty_tcxonc_locked(pair, false, (uintptr_t)arg, &notify_master,
                                &notify_slave);
        break;
    case TIOCGPGRP:
        ret = copy_to_user(arg, &pair->frontProcessGroup, sizeof(int)) ? -EFAULT
                                                                       : 0;
        break;
    case TIOCSPGRP:
        ret = copy_from_user(&pair->frontProcessGroup, arg, sizeof(int))
                  ? -EFAULT
                  : 0;
        break;
    case TIOCNOTTY:
    case VT_ACTIVATE:
    case VT_WAITACTIVE:
        ret = 0;
        break;
    default:
        printk("pts_ioctl: Unsupported request %#010lx\n", request);
        break;
    }
    mutex_unlock(&pair->lock);

    if (ret >= 0) {
        pty_notify_pair_master(pair, notify_master);
        pty_notify_pair_slave(pair, notify_slave);
    }
    return ret;
}

static long pts_ioctl_file(fd_t *fd, unsigned long request, unsigned long arg) {
    return pts_ioctl(pty_pair_from_file(fd), request, (void *)arg);
}

static ssize_t ptmx_read_file(struct vfs_file *fd, void *buf, size_t count,
                              loff_t *ppos) {
    (void)ppos;
    return ptmx_read(fd, buf, 0, count);
}

static ssize_t ptmx_write_file(struct vfs_file *fd, const void *buf,
                               size_t count, loff_t *ppos) {
    (void)ppos;
    return ptmx_write(fd, buf, 0, count);
}

static ssize_t pts_read_file(struct vfs_file *fd, void *buf, size_t count,
                             loff_t *ppos) {
    (void)ppos;
    return pts_read(fd, buf, 0, count);
}

static ssize_t pts_write_file(struct vfs_file *fd, const void *buf,
                              size_t count, loff_t *ppos) {
    (void)ppos;
    return pts_write(fd, buf, 0, count);
}

static __poll_t pts_poll(fd_t *file, struct vfs_poll_table *pt) {
    pty_pair_t *pair = pty_pair_from_file(file);
    int revents = 0;
    (void)pt;
    if (!pair)
        return EPOLLNVAL;

    mutex_lock(&pair->lock);
    if (pts_data_avail(pair) > 0)
        revents |= EPOLLIN;
    if (pair->ptrMaster < PTY_BUFF_SIZE)
        revents |= EPOLLOUT;
    if (!pair->masterFds)
        revents |= EPOLLHUP | EPOLLRDHUP;
    mutex_unlock(&pair->lock);
    return revents;
}

static loff_t pty_llseek(struct vfs_file *file, loff_t offset, int whence) {
    (void)file;
    (void)offset;
    (void)whence;
    return -ESPIPE;
}

static const struct vfs_file_operations ptmx_file_ops = {
    .llseek = pty_llseek,
    .read = ptmx_read_file,
    .write = ptmx_write_file,
    .unlocked_ioctl = ptmx_ioctl,
    .poll = ptmx_poll,
    .open = ptmx_open_file,
    .release = ptmx_release_file,
};

static const struct vfs_file_operations pts_file_ops = {
    .llseek = pty_llseek,
    .read = pts_read_file,
    .write = pts_write_file,
    .unlocked_ioctl = pts_ioctl_file,
    .poll = pts_poll,
    .open = pts_open_file,
    .release = pts_release_file,
};

void ptmx_init() {
    vfs_node_t *ptmx;

    (void)vfs_mknodat(AT_FDCWD, "/dev/ptmx", S_IFCHR | 0666, (5U << 8) | 2U);
    ptmx = pty_lookup_inode_path("/dev/ptmx");
    if (!ptmx)
        return;
    ptmx->i_fop = &ptmx_file_ops;
    ptmx->type = file_stream;
    vfs_iput(ptmx);
}

void pts_init() {
    (void)vfs_mkdirat(AT_FDCWD, "/dev/pts", 0755);
    if (first_pair.id == 0) {
        first_pair.id = 0xffffffff;
    }
}

void pts_repopulate_nodes() {
    pty_pair_t *pairs[PTY_MAX];
    size_t count = 0;
    pty_pair_t *pair;

    if (!pty_bitmap)
        return;

    spin_lock(&pty_global_lock);
    for (pair = first_pair.next; pair && count < PTY_MAX; pair = pair->next)
        pairs[count++] = pair;
    spin_unlock(&pty_global_lock);

    for (size_t i = 0; i < count; i++)
        (void)pty_pair_install_slave_node(pairs[i]);
}
