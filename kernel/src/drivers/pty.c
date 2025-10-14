#include <drivers/pty.h>

uint8_t *pty_bitmap = 0;
spinlock_t pty_global_lock = {0};

pty_pair_t first_pair;

static int ptmx_fsid = 0;
int pts_fsid = 0;

size_t pts_write_inner(pty_pair_t *pair, uint8_t *in, size_t limit);

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

void ptmx_open(void *parent, const char *name, vfs_node_t node) {
    int id = pty_bitmap_decide(); // here to avoid double locks
    spin_lock(&pty_global_lock);
    pty_pair_t *n = &first_pair;
    while (n->next) {
        n = n->next;
    }

    n->next = malloc(sizeof(pty_pair_t));
    pty_pair_t *pair = n->next;
    memset(pair, 0, sizeof(pty_pair_t));
    pair->id = id;
    pair->frontProcessGroup = -1;
    pair->bufferMaster = alloc_frames_bytes(PTY_BUFF_SIZE);
    pair->bufferSlave = alloc_frames_bytes(PTY_BUFF_SIZE);
    pty_termios_default(&pair->term);
    pair->win.ws_row = 24;
    pair->win.ws_col = 80; // some sane defaults
    pair->tty_kbmode = K_XLATE;
    memset(&pair->vt_mode, 0, sizeof(struct vt_mode));
    pair->masterFds = 1;
    pair->ptmx_node = node;
    node->handle = n->next;
    node->fsid = ptmx_fsid;

    vfs_node_t dev_root = node->parent;
    list_delete(dev_root->child, node);
    node->parent = NULL;
    vfs_node_t new_node = vfs_node_alloc(dev_root, "ptmx");
    new_node->fsid = ptmx_fsid;
    new_node->handle = NULL;

    vfs_node_t pts_node = vfs_open("/dev/pts");
    pts_node->fsid = pts_fsid;
    char nm[4];
    sprintf(nm, "%d", id);
    vfs_node_t pty_slave_node = vfs_node_alloc(pts_node, nm);
    pty_slave_node->fsid = pts_fsid;

    spin_unlock(&pty_global_lock);
}

void pty_pair_cleanup(pty_pair_t *pair) {
    free_frames_bytes(pair->bufferMaster, PTY_BUFF_SIZE);
    free_frames_bytes(pair->bufferSlave, PTY_BUFF_SIZE);
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

bool ptmx_close(void *current) {
    pty_pair_t *pair = current;
    spin_lock(&pair->lock);
    pair->masterFds--;
    if (!pair->masterFds && !pair->slaveFds)
        pty_pair_cleanup(pair);
    else
        spin_unlock(&pair->lock);
    free(pair->ptmx_node->name);
    free(pair->ptmx_node);
    return true;
}

// todo: control + d stuff
size_t ptmx_data_avail(pty_pair_t *pair) {
    return pair->ptrMaster; // won't matter here
}

size_t ptmx_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;
    while (true) {
        spin_lock(&pair->lock);
        if (ptmx_data_avail(pair) > 0) {
            spin_unlock(&pair->lock);
            break;
        }
        if (!pair->slaveFds) {
            spin_unlock(&pair->lock);
            return 0;
        }
        if (fd->flags & O_NONBLOCK) {
            spin_unlock(&pair->lock);
            return -(EWOULDBLOCK);
        }
        spin_unlock(&pair->lock);
        arch_yield();
    }

    spin_lock(&pair->lock);

    arch_disable_interrupt();

    size_t toCopy = MIN(size, ptmx_data_avail(pair));
    memcpy(addr, pair->bufferMaster, toCopy);
    memmove(pair->bufferMaster, &pair->bufferMaster[toCopy],
            PTY_BUFF_SIZE - toCopy);
    pair->ptrMaster -= toCopy;

    spin_unlock(&pair->lock);
    return toCopy;
}

extern void send_sigint(int pgid);

size_t ptmx_write(fd_t *fd, const void *addr, size_t offset, size_t limit) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;
    while (true) {
        spin_lock(&pair->lock);
        if ((pair->ptrSlave + limit) < PTY_BUFF_SIZE) {
            spin_unlock(&pair->lock);
            break;
        }
        if (fd->flags & O_NONBLOCK) {
            spin_unlock(&pair->lock);
            return -(EWOULDBLOCK);
        }
        spin_unlock(&pair->lock);
        arch_yield();
    }

    spin_lock(&pair->lock);

    memcpy(&pair->bufferSlave[pair->ptrSlave], addr, limit);
    if (pair->term.c_iflag & ICRNL)
        for (size_t i = 0; i < limit; i++) {
            if (pair->bufferSlave[pair->ptrSlave + i] == '\r')
                pair->bufferSlave[pair->ptrSlave + i] = '\n';
        }
    if (pair->term.c_lflag & ICANON && pair->term.c_lflag & ECHO) {
        pts_write_inner(pair, &pair->bufferSlave[pair->ptrSlave], limit);
    }
    pair->ptrSlave += limit;

    spin_unlock(&pair->lock);
    return limit;
}

size_t ptmx_ioctl(void *file, uint64_t request, uint64_t arg) {
    pty_pair_t *pair = file;
    size_t ret = 0; // todo ERR(ENOTTY)
    size_t number = _IOC_NR(request);

    spin_lock(&pair->lock);
    switch (number) {
    case 0x31: { // TIOCSPTLCK
        int lock = *((int *)arg);
        if (lock == 0)
            pair->locked = false;
        else
            pair->locked = true;
        ret = 0;
        goto done;
    }
    case 0x30: // TIOCGPTN
        *((int *)arg) = pair->id;
        ret = 0;
        goto done;
    }
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
    default:
        printk("ptmx_ioctl: Unsupported request %#010lx\n",
               request & 0xFFFFFFFF);
        break;
    }
done:
    spin_unlock(&pair->lock);

    return ret;
}

int ptmx_poll(void *file, size_t events) {
    pty_pair_t *pair = file;
    int revents = 0;

    spin_lock(&pair->lock);
    if (ptmx_data_avail(pair) > 0 && events & EPOLLIN)
        revents |= EPOLLIN;
    if (pair->ptrSlave < PTY_BUFF_SIZE && events & EPOLLOUT)
        revents |= EPOLLOUT;
    spin_unlock(&pair->lock);

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

void pts_open(void *parent, const char *name, vfs_node_t node) {
    int length = strlen(name);

    int id;
    int res = str_to_int(name, &id);
    if (res < 0)
        return;
    spin_lock(&pty_global_lock);
    pty_pair_t *browse = &first_pair;
    while (browse) {
        spin_lock(&browse->lock);
        if (browse->id == id)
            break;
        spin_unlock(&browse->lock);
        browse = browse->next;
    }
    spin_unlock(&pty_global_lock);

    if (!browse)
        return;

    if (browse->locked) {
        spin_unlock(&pty_global_lock);
        return;
    }

    node->handle = browse;
    node->type = file_pts;
    node->fsid = pts_fsid;
    browse->slaveFds++;

    spin_unlock(&browse->lock);
}

bool pts_close(void *fd) {
    pty_pair_t *pair = fd;
    spin_lock(&pair->lock);
    pair->slaveFds--;
    if (!pair->masterFds && !pair->slaveFds)
        pty_pair_cleanup(pair);
    else
        spin_unlock(&pair->lock);
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
    while (true) {
        spin_lock(&pair->lock);
        if (pts_data_avali(pair) > 0) {
            spin_unlock(&pair->lock);
            break;
        }
        if (!pair->masterFds) {
            spin_unlock(&pair->lock);
            return 0;
        }
        if (fd->flags & O_NONBLOCK) {
            spin_unlock(&pair->lock);
            return -(EWOULDBLOCK);
        }
        spin_unlock(&pair->lock);
        arch_yield();
    }

    spin_lock(&pair->lock);

    arch_disable_interrupt();

    size_t toCopy = MIN(limit, pts_data_avali(pair));
    memcpy(out, pair->bufferSlave, toCopy);
    memmove(pair->bufferSlave, &pair->bufferSlave[toCopy],
            PTY_BUFF_SIZE - toCopy);
    pair->ptrSlave -= toCopy;

    spin_unlock(&pair->lock);
    return toCopy;
}

size_t pts_write_inner(pty_pair_t *pair, uint8_t *in, size_t limit) {
    size_t written = 0;
    bool doTranslate =
        (pair->term.c_oflag & OPOST) && (pair->term.c_oflag & ONLCR);
    for (size_t i = 0; i < limit; ++i) {
        uint8_t ch = in[i];
        if (doTranslate && ch == '\n') {
            if ((pair->ptrMaster + 2) >= PTY_BUFF_SIZE)
                break;
            pair->bufferMaster[pair->ptrMaster++] = '\r';
            pair->bufferMaster[pair->ptrMaster++] = '\n';
            written++;
        } else {
            if ((pair->ptrMaster + 1) >= PTY_BUFF_SIZE)
                break;
            pair->bufferMaster[pair->ptrMaster++] = ch;
            written++;
        }
    }
    return written;
}

size_t pts_write(fd_t *fd, uint8_t *in, size_t offset, size_t limit) {
    void *file = fd->node->handle;
    pty_pair_t *pair = file;

    while (true) {
        spin_lock(&pair->lock);
        if (!pair->masterFds) {
            spin_unlock(&pair->lock);
            // todo: send SIGHUP when master is closed, check controlling
            // term/group
            return (size_t)-EIO;
        }
        if ((pair->ptrMaster + limit) < PTY_BUFF_SIZE) {
            spin_unlock(&pair->lock);
            break;
        }
        if (fd->flags & O_NONBLOCK) {
            spin_unlock(&pair->lock);
            return -(EWOULDBLOCK);
        }
        spin_unlock(&pair->lock);
        arch_yield();
    }

    spin_lock(&pair->lock);

    // we already have a lock in our hands
    size_t written = pts_write_inner(pair, in, limit);

    spin_unlock(&pair->lock);
    return written;
}

size_t pts_ioctl(pty_pair_t *pair, uint64_t request, void *arg) {
    size_t ret = -ENOTTY;

    spin_lock(&pair->lock);
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
    case TCSETS:
    case TCSETSW:   // this drains(?), idek man
    case TCSETSF: { // idek anymore man
        memcpy(&pair->term, arg, sizeof(termios));
        ret = 0;
        break;
    }
    case TIOCGPGRP:
        int *pid = (int *)arg;
        *pid = current_task->pid;
        ret = 0;
        break;
    case TIOCSPGRP:
        pair->frontProcessGroup = *(int *)arg;
        ret = 0;
        break;
    case KDGKBMODE:
        *(int *)arg = pair->tty_kbmode;
        return 0;
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
    spin_unlock(&pair->lock);

    return ret;
}

int pts_poll(pty_pair_t *pair, int events) {
    int revents = 0;

    spin_lock(&pair->lock);
    if ((!pair->masterFds || pts_data_avali(pair) > 0) && events & EPOLLIN)
        revents |= EPOLLIN;
    if (pair->ptrMaster < PTY_BUFF_SIZE && events & EPOLLOUT)
        revents |= EPOLLOUT;
    spin_unlock(&pair->lock);

    return revents;
}

vfs_node_t ptmx_dup(vfs_node_t node) {
    pty_pair_t *pair = node->handle;
    // spin_lock(&pair->lock);
    // pair->masterFds++;
    // spin_unlock(&pair->lock);
    return node;
}

vfs_node_t pts_dup(vfs_node_t node) {
    pty_pair_t *pair = node->handle;
    // spin_lock(&pair->lock);
    // pair->slaveFds++;
    // spin_unlock(&pair->lock);
    return node;
}

static int dummy() { return 0; }

static struct vfs_callback ptmx_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)ptmx_open,
    .close = (vfs_close_t)ptmx_close,
    .read = (vfs_read_t)ptmx_read,
    .write = (vfs_write_t)ptmx_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)ptmx_ioctl,
    .poll = ptmx_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)ptmx_dup,

    .free_handle = vfs_generic_free_handle,
};

static struct vfs_callback pts_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)pts_open,
    .close = (vfs_close_t)pts_close,
    .read = (vfs_read_t)pts_read,
    .write = (vfs_write_t)pts_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)pts_ioctl,
    .poll = (vfs_poll_t)pts_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = (vfs_dup_t)pts_dup,

    .free_handle = vfs_generic_free_handle,
};

fs_t ptmxfs = {
    .name = "ptmx",
    .magic = 0,
    .callback = &ptmx_callbacks,
};

void ptmx_init() {
    ptmx_fsid = vfs_regist(&ptmxfs);

    vfs_node_t dev_node = vfs_open("/dev");
    vfs_node_t ptmx = vfs_child_append(dev_node, "ptmx", NULL);
    ptmx->type = file_ptmx;
    ptmx->mode = 0700;
    ptmx->fsid = ptmx_fsid;
}

extern vfs_node_t devfs_root;

fs_t ptsfs = {
    .name = "ptsfs",
    .magic = 0,
    .callback = &pts_callbacks,
};

void pts_init() {
    pts_fsid = vfs_regist(&ptsfs);

    first_pair.id = 0xffffffff;

    vfs_node_t pts_node = vfs_child_append(devfs_root, "pts", NULL);
    pts_node->fsid = pts_fsid;
    pts_node->type = file_dir;
    pts_node->mode = 0644;
    pts_node->handle = pts_node;
}
