#include <drivers/pty.h>
#include <task/task.h>

uint8_t *pty_bitmap = 0;
spinlock_t pty_global_lock = SPIN_INIT;

pty_pair_t first_pair;

static int ptmx_fsid = 0;
int pts_fsid = 0;

extern vfs_node_t devtmpfs_root;

size_t pts_write_inner(fd_t *fd, uint8_t *in, size_t limit);
extern void send_process_group_signal(int pgid, int sig);

static inline void pty_notify_node(vfs_node_t node, uint32_t events) {
    if (!node || !events)
        return;
    vfs_poll_notify(node, events);
}

static inline void pty_notify_pair_master(pty_pair_t *pair, uint32_t events) {
    if (!pair)
        return;
    pty_notify_node(pair->ptmx_node, events);
}

static inline void pty_notify_pair_slave(pty_pair_t *pair, uint32_t events) {
    if (!pair)
        return;
    pty_notify_node(pair->pts_node, events);
}

static int pty_wait_node(vfs_node_t node, uint32_t events, const char *reason) {
    if (!node || !current_task)
        return -EINVAL;

    uint32_t want = events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    if (vfs_poll(node, want) & want)
        return EOK;

    vfs_poll_wait_t wait;
    vfs_poll_wait_init(&wait, current_task, want);
    if (vfs_poll_wait_arm(node, &wait) < 0)
        return -EINVAL;
    int ret = vfs_poll_wait_sleep(node, &wait, -1, reason);
    vfs_poll_wait_disarm(&wait);
    return ret;
}

static int pty_tcxonc_locked(pty_pair_t *pair, bool from_master,
                             uintptr_t arg, uint32_t *notify_master,
                             uint32_t *notify_slave) {
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
        uint8_t flow_char =
            pair->term.c_cc[action == TCIOFF ? VSTOP : VSTART];
        if (from_master) {
            if (!pair->slaveFds)
                return 0;
            if (pair->ptrSlave >= PTY_BUFF_SIZE)
                return -EAGAIN;
            pair->bufferSlave[pair->ptrSlave++] = flow_char;
            if (notify_slave)
                *notify_slave |= EPOLLIN;
        } else {
            if (!pair->masterFds)
                return 0;
            if (pair->ptrMaster >= PTY_BUFF_SIZE)
                return -EAGAIN;
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

    term->c_cc[VINTR] = 3;    // Ctrl-C
    term->c_cc[VQUIT] = 28;   // Ctrl-backslash
    term->c_cc[VERASE] = 127; // DEL
    term->c_cc[VKILL] = 21;   // Ctrl-U
    term->c_cc[VEOF] = 4;     // Ctrl-D
    term->c_cc[VTIME] = 0;
    term->c_cc[VMIN] = 1;
    term->c_cc[VSTART] = 17; // Ctrl-Q
    term->c_cc[VSTOP] = 19;  // Ctrl-S
    term->c_cc[VSUSP] = 26;  // Ctrl-Z
}

void pty_init() { pty_bitmap = calloc(PTY_MAX / 8, 1); }

void ptmx_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    int id = pty_bitmap_decide(); // here to avoid double locks
    if (id < 0)
        return;

    pty_pair_t *pair = malloc(sizeof(pty_pair_t));
    if (!pair) {
        pty_bitmap_remove(id);
        return;
    }

    memset(pair, 0, sizeof(pty_pair_t));
    mutex_init(&pair->lock);
    pair->id = id;
    pair->frontProcessGroup = 0;
    pair->bufferMaster = alloc_frames_bytes(PTY_BUFF_SIZE);
    pair->bufferSlave = alloc_frames_bytes(PTY_BUFF_SIZE);
    pty_termios_default(&pair->term);
    pair->win.ws_row = 24;
    pair->win.ws_col = 80; // some sane defaults
    pair->tty_kbmode = K_XLATE;
    memset(&pair->vt_mode, 0, sizeof(struct vt_mode));
    pair->masterFds = 1;
    pair->ptmx_node = node;
    pair->pts_node = NULL;
    node->handle = pair;
    node->fsid = ptmx_fsid;

    spin_lock(&pty_global_lock);
    pty_pair_t *n = &first_pair;
    while (n->next) {
        n = n->next;
    }
    n->next = pair;
    spin_unlock(&pty_global_lock);

    llist_delete(&node->node_for_childs);
    node->parent = NULL;
    vfs_node_t new_node = vfs_node_alloc(devtmpfs_root, "ptmx");
    new_node->fsid = ptmx_fsid;
    new_node->handle = NULL;

    vfs_node_t pts_node = vfs_open_at(devtmpfs_root, "pts", 0);
    pts_node->fsid = pts_fsid;
    char nm[12];
    sprintf(nm, "%d", id);
    vfs_node_t pty_slave_node = vfs_node_alloc(pts_node, nm);
    pty_slave_node->fsid = pts_fsid;
    pty_slave_node->type = file_stream;
    pty_slave_node->handle = pair;
    pair->pts_node = pty_slave_node;
    pair->slaveFds++;
}

void pty_pair_cleanup(pty_pair_t *pair) {
    free_frames_bytes(pair->bufferMaster, PTY_BUFF_SIZE);
    free_frames_bytes(pair->bufferSlave, PTY_BUFF_SIZE);
    pair->ptmx_node = NULL;
    pair->pts_node = NULL;
    pty_bitmap_remove(pair->id);

    spin_lock(&pty_global_lock);
    pty_pair_t *n = &first_pair;
    while (n->next && n->next != pair) {
        n = n->next;
    }
    if (n->next) {
        n->next = pair->next;
    }
    spin_unlock(&pty_global_lock);
}

void ptmx_free_handle(vfs_node_t node) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return;
    if (pair->ptmx_node == node)
        pair->ptmx_node = NULL;
    pair->masterFds--;
    if (!pair->masterFds && !pair->slaveFds) {
        pty_pair_cleanup(pair);
    }
}

void pts_free_handle(vfs_node_t node) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return;
    if (pair->pts_node == node)
        pair->pts_node = NULL;
    pair->slaveFds--;
    if (!pair->masterFds && !pair->slaveFds) {
        pty_pair_cleanup(pair);
    }
}

bool ptmx_close(vfs_node_t node) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return true;
    pair->masterFds--;
    pair->ptmx_node = NULL;
    pty_notify_pair_slave(pair, EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (!pair->masterFds && !pair->slaveFds) {
        pty_pair_cleanup(pair);
    }
    return true;
}

size_t ptmx_data_avail(pty_pair_t *pair) { return pair->ptrMaster; }

size_t ptmx_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;
    if (!pair)
        return (size_t)-EINVAL;

    while (true) {
        mutex_lock(&pair->lock);

        if (ptmx_data_avail(pair) > 0) {
            size_t toCopy = MIN(size, ptmx_data_avail(pair));
            memcpy(addr, pair->bufferMaster, toCopy);
            size_t remaining = pair->ptrMaster - toCopy;
            if (remaining > 0) {
                memmove(pair->bufferMaster, &pair->bufferMaster[toCopy],
                        remaining);
            }
            pair->ptrMaster -= toCopy;
            mutex_unlock(&pair->lock);

            pty_notify_pair_slave(pair, EPOLLOUT);
            return toCopy;
        }

        bool no_slave = (pair->slaveFds == 0);
        mutex_unlock(&pair->lock);

        if (no_slave)
            return 0;
        if (fd->flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        int reason = pty_wait_node(fd->node, EPOLLIN, "ptmx_read");
        if (reason != EOK)
            return -EINTR;
    }
}

size_t ptmx_write(fd_t *fd, const void *addr, size_t offset, size_t limit) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;
    if (!pair)
        return (size_t)-EINVAL;

    while (true) {
        mutex_lock(&pair->lock);

        if (pair->stop_master_output) {
            mutex_unlock(&pair->lock);
            if (fd->flags & O_NONBLOCK)
                return -EWOULDBLOCK;
            int reason = pty_wait_node(fd->node, EPOLLOUT, "ptmx_tcooff");
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
            size_t written = 0;
            size_t echoed = 0;
            size_t echo_start = pair->ptrSlave;
            for (size_t i = 0; i < limit; i++) {
                uint8_t ch = in[i];
                if (pair->term.c_lflag & ISIG) {
                    uint64_t pgid = pair->frontProcessGroup;
                    if (!pgid)
                        pgid = pair->ctrlPgid;
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
                if ((pair->ptrSlave + 1) > PTY_BUFF_SIZE)
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
            return written;
        }

        mutex_unlock(&pair->lock);

        if (fd->flags & O_NONBLOCK) {
            return -EWOULDBLOCK;
        }

        int reason = pty_wait_node(fd->node, EPOLLOUT, "ptmx_write");
        if (reason != EOK)
            return -EINTR;
    }
}

int ptmx_ioctl(vfs_node_t node, ssize_t request, ssize_t arg) {
    if (!node || !node->handle)
        return -EINVAL;
    pty_pair_t *pair = node->handle;
    int ret = -ENOTTY;
    uint32_t notify_master = 0;
    uint32_t notify_slave = 0;
    size_t number = _IOC_NR(request);

    mutex_lock(&pair->lock);
    switch (number) {
    case 0x31: { // TIOCSPTLCK
        int lock = *((int *)arg);
        if (lock == 0)
            pair->locked = false;
        else
            pair->locked = true;
        ret = 0;
        break;
    }
    case 0x30: // TIOCGPTN
        *((int *)arg) = pair->id;
        ret = 0;
        break;
    }
    if (ret == -ENOTTY) {
        switch (request & 0xFFFFFFFF) {
        case TIOCGWINSZ: {
            memcpy((void *)arg, &pair->win, sizeof(struct winsize));
            ret = 0;
            break;
        }
        case TIOCSWINSZ: {
            memcpy(&pair->win, (const void *)arg, sizeof(struct winsize));
            ret = 0;
            break;
        }
        case TCXONC:
            ret = pty_tcxonc_locked(pair, true, (uintptr_t)arg, &notify_master,
                                    &notify_slave);
            break;
        default:
            printk("ptmx_ioctl: Unsupported request %#010lx\n",
                   request & 0xFFFFFFFF);
            break;
        }
    }
    mutex_unlock(&pair->lock);
    if (!ret) {
        pty_notify_pair_master(pair, notify_master);
        pty_notify_pair_slave(pair, notify_slave);
    }

    return ret;
}

int ptmx_poll(vfs_node_t node, size_t events) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return EPOLLNVAL;
    int revents = 0;

    mutex_lock(&pair->lock);
    if ((events & EPOLLIN) && ptmx_data_avail(pair) > 0)
        revents |= EPOLLIN;
    if ((events & EPOLLOUT) && pair->ptrSlave < PTY_BUFF_SIZE)
        revents |= EPOLLOUT;
    if (!pair->slaveFds)
        revents |= EPOLLHUP | EPOLLRDHUP;
    mutex_unlock(&pair->lock);

    return revents;
}

void pts_ctrl_assign(pty_pair_t *pair) {
    // currentTask->ctrlPty = pair->id;
    pair->ctrlSession = current_task->sid;
    pair->ctrlPgid = current_task->pgid;
    // debugf("heck yeah! %d %d\n", currentTask->id, pair->id);
}

int str_to_int(const char *str, int *result) {
    int sign = 1;
    long value = 0;

    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    for (; *str != '\0'; str++) {
        if (!(*str >= '0' && *str <= '9')) {
            return -EINVAL;
        }

        value = value * 10 + (*str - '0');
    }

    value *= sign;

    *result = (int)value;
    return 0;
}

void pts_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    int id;
    int res = str_to_int(name, &id);
    if (res < 0)
        return;

    spin_lock(&pty_global_lock);
    pty_pair_t *browse = &first_pair;
    while (browse) {
        if (browse->id == id) {
            break;
        }
        browse = browse->next;
    }
    spin_unlock(&pty_global_lock);

    if (!browse)
        return;

    if (browse->locked) {
        return;
    }

    mutex_lock(&browse->lock);

    node->handle = browse;
    node->type = file_stream;
    node->fsid = pts_fsid;
    browse->pts_node = node;
    browse->slaveFds++;

    mutex_unlock(&browse->lock);
}

bool pts_close(vfs_node_t node) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return true;
    pair->slaveFds--;
    if (pair->pts_node == node)
        pair->pts_node = NULL;
    pty_notify_pair_master(pair, EPOLLHUP | EPOLLRDHUP | EPOLLERR);
    if (!pair->masterFds && !pair->slaveFds) {
        pty_pair_cleanup(pair);
    }
    return true;
}

size_t pts_data_avali(pty_pair_t *pair) {
    bool canonical = pair->term.c_lflag & ICANON;
    if (!canonical)
        return pair->ptrSlave; // flush whatever we can

    // now we're on canonical mode
    for (size_t i = 0; i < pair->ptrSlave; i++) {
        if (pair->bufferSlave[i] == '\n' ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOF] ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOL] ||
            pair->bufferSlave[i] == pair->term.c_cc[VEOL2])
            return i + 1; // +1 for len
    }

    return 0; // nothing found
}

size_t pts_read(fd_t *fd, uint8_t *out, size_t offset, size_t limit) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;
    if (!pair)
        return (size_t)-EINVAL;

    while (true) {
        mutex_lock(&pair->lock);

        if (pts_data_avali(pair) > 0) {
            size_t toCopy = MIN(limit, pts_data_avali(pair));
            memcpy(out, pair->bufferSlave, toCopy);
            size_t remaining = pair->ptrSlave - toCopy;
            if (remaining > 0) {
                memmove(pair->bufferSlave, &pair->bufferSlave[toCopy],
                        remaining);
            }
            pair->ptrSlave -= toCopy;
            mutex_unlock(&pair->lock);

            pty_notify_pair_master(pair, EPOLLOUT);
            return toCopy;
        }

        bool no_master = (pair->masterFds == 0);
        mutex_unlock(&pair->lock);

        if (no_master)
            return 0;
        if (fd->flags & O_NONBLOCK) {
            return -EWOULDBLOCK;
        }

        int reason = pty_wait_node(fd->node, EPOLLIN, "pts_read");
        if (reason != EOK)
            return -EINTR;
    }
}

size_t pts_write_inner(fd_t *fd, uint8_t *in, size_t limit) {
    pty_pair_t *pair = fd->node->handle;
    if (!pair)
        return (size_t)-EINVAL;

    while (true) {
        mutex_lock(&pair->lock);

        if (pair->stop_slave_output) {
            mutex_unlock(&pair->lock);
            if (fd->flags & O_NONBLOCK)
                return -EWOULDBLOCK;
            int reason = pty_wait_node(fd->node, EPOLLOUT, "pts_tcooff");
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
            bool doTranslate =
                (pair->term.c_oflag & OPOST) && (pair->term.c_oflag & ONLCR);
            for (size_t i = 0; i < limit; ++i) {
                uint8_t ch = in[i];
                if (doTranslate && ch == '\n') {
                    if ((pair->ptrMaster + 2) > PTY_BUFF_SIZE)
                        break;
                    pair->bufferMaster[pair->ptrMaster++] = '\r';
                    pair->bufferMaster[pair->ptrMaster++] = '\n';
                } else {
                    if ((pair->ptrMaster + 1) > PTY_BUFF_SIZE)
                        break;
                    pair->bufferMaster[pair->ptrMaster++] = ch;
                }
                written++;
            }

            mutex_unlock(&pair->lock);
            if (written > 0)
                pty_notify_pair_master(pair, EPOLLIN);
            return written;
        }

        mutex_unlock(&pair->lock);

        if (fd->flags & O_NONBLOCK)
            return -EWOULDBLOCK;

        vfs_node_t wait_node = pair->pts_node ? pair->pts_node : fd->node;
        int reason = pty_wait_node(wait_node, EPOLLOUT, "pts_write");
        if (reason != EOK)
            return -EINTR;
    }
}

size_t pts_write(fd_t *fd, uint8_t *in, size_t offset, size_t limit) {
    int ret = 0;
    pty_pair_t *pair = fd->node->handle;
    if (!pair)
        return (size_t)-EINVAL;
    size_t chunks = limit / PTY_BUFF_SIZE;
    size_t remainder = limit % PTY_BUFF_SIZE;
    if (chunks)
        for (size_t i = 0; i < chunks; i++) {
            int cycle = 0;
            while (cycle < PTY_BUFF_SIZE) {
                size_t r = pts_write_inner(fd, in + i * PTY_BUFF_SIZE + cycle,
                                           PTY_BUFF_SIZE - cycle);
                if ((ssize_t)r < 0)
                    return r;
                if (r == 0) {
                    if (fd->flags & O_NONBLOCK)
                        return ret ? ret : (size_t)-EWOULDBLOCK;
                    int reason = pty_wait_node(fd->node, EPOLLOUT, "pts_write");
                    if (reason != EOK)
                        return ret ? ret : (size_t)-EINTR;
                    continue;
                }
                cycle += r;
            }

            ret += cycle;
        }

    if (remainder) {
        size_t cycle = 0;
        while (cycle < remainder) {
            size_t r = pts_write_inner(fd, in + chunks * PTY_BUFF_SIZE + cycle,
                                       remainder - cycle);
            if ((ssize_t)r < 0)
                return r;
            if (r == 0) {
                if (fd->flags & O_NONBLOCK)
                    return ret ? ret : (size_t)-EWOULDBLOCK;
                int reason = pty_wait_node(fd->node, EPOLLOUT, "pts_write");
                if (reason != EOK)
                    return ret ? ret : (size_t)-EINTR;
                continue;
            }
            cycle += r;
        }
        ret += cycle;
    }

    return ret;
}

size_t pts_ioctl(pty_pair_t *pair, uint64_t request, void *arg) {
    if (!pair)
        return (size_t)-EINVAL;

    size_t ret = -ENOTTY;
    uint32_t notify_master = 0;
    uint32_t notify_slave = 0;

    mutex_lock(&pair->lock);
    switch (request) {
    case TIOCGWINSZ: {
        memcpy(arg, &pair->win, sizeof(struct winsize));
        ret = 0;
        break;
    }
    case TIOCSWINSZ: {
        memcpy(&pair->win, arg, sizeof(struct winsize));
        ret = 0;
        break;
    }
    case TIOCSCTTY: {
        pts_ctrl_assign(pair);
        ret = 0;
        break;
    }
    case TCGETS: {
        memcpy(arg, &pair->term, sizeof(termios));
        ret = 0;
        break;
    }
    case TCGETS2:
        struct termios2 t2;
        memcpy(&t2.c_iflag, &pair->term.c_iflag, sizeof(uint32_t));
        memcpy(&t2.c_oflag, &pair->term.c_oflag, sizeof(uint32_t));
        memcpy(&t2.c_cflag, &pair->term.c_cflag, sizeof(uint32_t));
        memcpy(&t2.c_lflag, &pair->term.c_lflag, sizeof(uint32_t));
        t2.c_line = pair->term.c_line;
        memcpy(t2.c_cc, pair->term.c_cc, NCCS);
        t2.c_ispeed = 0; // Not supported
        t2.c_ospeed = 0; // Not supported
        memcpy((void *)arg, &t2, sizeof(struct termios2));
        ret = 0;
        break;
    case TCSETS:
    case TCSETSW:
    case TCSETSF: {
        memcpy(&pair->term, arg, sizeof(termios));
        ret = 0;
        break;
    }
    case TCSETS2:
        struct termios2 t2_set;
        memcpy(&t2_set, (void *)arg, sizeof(struct termios2));
        memcpy(&pair->term.c_iflag, &t2_set.c_iflag, sizeof(uint32_t));
        memcpy(&pair->term.c_oflag, &t2_set.c_oflag, sizeof(uint32_t));
        memcpy(&pair->term.c_cflag, &t2_set.c_cflag, sizeof(uint32_t));
        memcpy(&pair->term.c_lflag, &t2_set.c_lflag, sizeof(uint32_t));
        pair->term.c_line = t2_set.c_line;
        memcpy(pair->term.c_cc, t2_set.c_cc, NCCS);
        // Ignore ispeed and ospeed as they are not supported
        ret = 0;
        break;
    case TCXONC:
        ret = pty_tcxonc_locked(pair, false, (uintptr_t)arg, &notify_master,
                                &notify_slave);
        break;
    case TIOCGPGRP:
        ret = copy_to_user(arg, (const void *)&pair->frontProcessGroup,
                           sizeof(int))
                  ? -EFAULT
                  : 0;
        break;
    case TIOCSPGRP:
        ret = copy_from_user(&pair->frontProcessGroup, (const void *)arg,
                             sizeof(int))
                  ? -EFAULT
                  : 0;
        break;
    case KDGKBMODE:
        *(int *)arg = pair->tty_kbmode;
        break;
    case KDSKBMODE:
        pair->tty_kbmode = *(int *)arg;
        ret = 0;
        break;
    case VT_SETMODE:
        memcpy(&pair->vt_mode, (void *)arg, sizeof(struct vt_mode));
        ret = 0;
        break;
    case VT_GETMODE:
        memcpy((void *)arg, &pair->vt_mode, sizeof(struct vt_mode));
        ret = 0;
        break;
    case VT_ACTIVATE:
        ret = 0;
        break;
    case VT_WAITACTIVE:
        ret = 0;
        break;
    case VT_GETSTATE:
        struct vt_state *state = (struct vt_state *)arg;
        state->v_active = 2; // 当前活动终端
        state->v_state = 0;  // 状态标志
        ret = 0;
        break;
    case VT_OPENQRY:
        *(int *)arg = 2;
        ret = 0;
        break;
    case TIOCNOTTY:
        ret = 0;
        break;
    default:
        printk("pts_ioctl: Unsupported request %#010lx\n", request);
        break;
    }
    mutex_unlock(&pair->lock);
    if (!ret) {
        pty_notify_pair_master(pair, notify_master);
        pty_notify_pair_slave(pair, notify_slave);
    }

    return ret;
}

int pts_poll(vfs_node_t node, size_t events) {
    pty_pair_t *pair = node ? node->handle : NULL;
    if (!pair)
        return EPOLLNVAL;
    int revents = 0;

    mutex_lock(&pair->lock);
    if ((events & EPOLLIN) && pts_data_avali(pair) > 0)
        revents |= EPOLLIN;
    if ((events & EPOLLOUT) && pair->ptrMaster < PTY_BUFF_SIZE)
        revents |= EPOLLOUT;
    if (!pair->masterFds)
        revents |= EPOLLHUP | EPOLLRDHUP;
    mutex_unlock(&pair->lock);

    return revents;
}

vfs_node_t ptmx_dup(vfs_node_t node) {
    pty_pair_t *pair = node->handle;
    // mutex_lock(&pair->lock);
    // pair->masterFds++;
    // mutex_unlock(&pair->lock);
    return node;
}

vfs_node_t pts_dup(vfs_node_t node) {
    pty_pair_t *pair = node->handle;
    // mutex_lock(&pair->lock);
    // pair->slaveFds++;
    // mutex_unlock(&pair->lock);
    return node;
}

static ssize_t ptmx_read_op(fd_t *fd, void *addr, size_t offset, size_t size) {
    return (ssize_t)ptmx_read(fd, addr, offset, size);
}

static ssize_t ptmx_write_op(fd_t *fd, const void *addr, size_t offset,
                             size_t size) {
    return (ssize_t)ptmx_write(fd, addr, offset, size);
}

static ssize_t pts_read_op(fd_t *fd, void *addr, size_t offset, size_t size) {
    return (ssize_t)pts_read(fd, (uint8_t *)addr, offset, size);
}

static ssize_t pts_write_op(fd_t *fd, const void *addr, size_t offset,
                            size_t size) {
    return (ssize_t)pts_write(fd, (uint8_t *)addr, offset, size);
}

static int pts_ioctl_node(vfs_node_t node, ssize_t request, ssize_t arg) {
    return (int)pts_ioctl(node ? node->handle : NULL, (uint64_t)request,
                          (void *)arg);
}

static vfs_operations_t ptmx_vfs_ops = {
    .open = ptmx_open,
    .close = ptmx_close,
    .read = ptmx_read_op,
    .write = ptmx_write_op,
    .ioctl = ptmx_ioctl,
    .poll = ptmx_poll,
    .free_handle = ptmx_free_handle,
};

static vfs_operations_t pts_vfs_ops = {
    .open = pts_open,
    .close = pts_close,
    .read = pts_read_op,
    .write = pts_write_op,
    .ioctl = pts_ioctl_node,
    .poll = pts_poll,
    .free_handle = pts_free_handle,
};

fs_t ptmxfs = {
    .name = "ptmx",
    .magic = 0,
    .ops = &ptmx_vfs_ops,
    .flags = FS_FLAGS_HIDDEN,
};

void ptmx_init() {
    ptmx_fsid = vfs_regist(&ptmxfs);

    vfs_node_t ptmx = vfs_child_append(devtmpfs_root, "ptmx", NULL);
    ptmx->type = file_stream;
    ptmx->mode = 0700;
    ptmx->fsid = ptmx_fsid;
    ptmx->dev = (5 << 8) | 2;
    ptmx->rdev = (5 << 8) | 2;
}

fs_t ptsfs = {
    .name = "ptsfs",
    .magic = 0,
    .ops = &pts_vfs_ops,
    .flags = FS_FLAGS_HIDDEN,
};

void pts_init() {
    pts_fsid = vfs_regist(&ptsfs);

    first_pair.id = 0xffffffff;

    vfs_node_t pts_node = vfs_child_append(devtmpfs_root, "pts", NULL);
    pts_node->fsid = pts_fsid;
    pts_node->type = file_dir;
    pts_node->mode = 0644;
}
