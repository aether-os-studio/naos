#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

static int notifyfs_id = 0;

static int watch_desc = 1;

struct llist_header all_watches;

typedef struct notifyfs_watch {
    uint64_t wd;
    vfs_node_t watch_node;
    uint64_t mask;
    uint64_t event;
    struct llist_header node;
    struct llist_header all_watches_node;
} notifyfs_watch_t;

typedef struct notifyfs_handle {
    struct llist_header watches;
    vfs_node_t node;
} notifyfs_handle_t;

static int dummy() { return 0; }

struct inotify_event {
    int wd;
    unsigned int mask;
    unsigned int cookie;
    unsigned int len;
    char name[];
};

ssize_t notifyfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    notifyfs_handle_t *handle = fd->node->handle;
    if (!handle)
        return -EINVAL;

    struct inotify_event *write_pos = (struct inotify_event *)addr;

    uint64_t total_write = 0;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        if (pos->event) {
            char *node_path = vfs_get_fullpath(pos->watch_node);
            size_t path_len = strlen(node_path) + 1;
            size_t total_len = sizeof(struct inotify_event) + path_len;
            if ((uint64_t)write_pos - (uint64_t)addr + total_len > size)
                break;
            pos->event = 0;
            strcpy(write_pos->name, node_path);
            write_pos->name[path_len] = '\0';
            write_pos->wd = pos->wd;
            write_pos->mask = pos->event;
            write_pos->len = path_len;
            write_pos->cookie = 0;
            total_write += total_len;
        }
    }

    return total_write;
}

static int notifyfs_poll(void *file, size_t events) {
    int revents = 0;

    notifyfs_handle_t *handle = file;
    notifyfs_watch_t *pos, *tmp;
    if (events & EPOLLIN) {
        llist_for_each(pos, tmp, &handle->watches, node) {
            vfs_node_t node = pos->watch_node;
            if (!node)
                continue;
            if (pos->mask & IN_MODIFY) {
                // TODO: Check content
                uint64_t old_size = node->size;
                vfs_update(node);
                if (node->size != old_size) {
                    pos->event |= IN_MODIFY;
                    revents |= EPOLLIN;
                }
            }
            if (pos->mask & IN_CREATE) {
                if (node->flags & VFS_NODE_FLAGS_CHILD_CREATED) {
                    node->flags &= ~VFS_NODE_FLAGS_CHILD_CREATED;
                    pos->event |= IN_CREATE;
                    revents |= EPOLLIN;
                }
            }
        }
    }

    return revents;
}

static bool notifyfs_close(void *current) {
    notifyfs_handle_t *handle = current;
    handle->node->flags |= VFS_NODE_FLAGS_DELETED;
    return true;
}

static struct vfs_callback notifyfs_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)notifyfs_close,
    .read = (vfs_read_t)notifyfs_read,
    .write = (vfs_write_t)dummy,
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
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)notifyfs_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t notifyfs_fs = {
    .name = "notifyfs",
    .magic = 0,
    .callback = &notifyfs_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

uint64_t sys_inotify_init1(uint64_t flags) {
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        return (uint64_t)-EMFILE;
    }

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->type = file_none;
    node->fsid = notifyfs_id;
    node->handle = NULL;
    node->refcount++;
    node->size = 0;
    notifyfs_handle_t *handle = malloc(sizeof(notifyfs_handle_t));
    node->handle = handle;
    handle->node = node;
    llist_init_head(&handle->watches);
    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->flags = 0;
    procfs_on_open_file(current_task, fd);

    return fd;
}

uint64_t sys_inotify_init() { return sys_inotify_init1(0); }

uint64_t sys_inotify_add_watch(uint64_t notifyfd, const char *path_user,
                               uint64_t mask) {
    if (notifyfd == SPECIAL_FD)
        return 0;

    if (notifyfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[notifyfd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t notify_node = current_task->fd_info->fds[notifyfd]->node;
    if (notify_node->fsid != notifyfs_id) {
        return (uint64_t)-EINVAL;
    }
    notifyfs_handle_t *handle = notify_node->handle;
    if (!handle) {
        return -EINVAL;
    }

    char path[256];
    if (copy_from_user_str(path, path_user, sizeof(path)))
        return (uint64_t)-EFAULT;

    vfs_node_t node = vfs_open(path);
    if (!node)
        return (uint64_t)-ENOENT;
    node = vfs_get_real_node(node);
    if (!node)
        return (uint64_t)-ENOENT;

    notifyfs_watch_t *watch = malloc(sizeof(notifyfs_watch_t));
    watch->watch_node = node;
    node->flags &= ~VFS_NODE_FLAGS_NOTIFY_MASK;
    watch->wd = watch_desc++;
    watch->mask = mask;
    watch->event = 0;

    llist_init_head(&watch->node);
    llist_prepend(&handle->watches, &watch->node);

    llist_init_head(&watch->all_watches_node);
    llist_prepend(&all_watches, &watch->all_watches_node);

    return 0;
}

uint64_t sys_inotify_rm_watch(uint64_t watchdesc, uint64_t mask) {
    notifyfs_watch_t *watch = NULL;
    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &all_watches, all_watches_node) {
        if (pos->wd == watchdesc) {
            watch = pos;
            break;
        }
    }

    if (!watch)
        return (uint64_t)-EBADF;

    llist_delete(&watch->node);
    llist_delete(&watch->all_watches_node);
    free(watch);

    return 0;
}

void notifyfs_init() {
    llist_init_head(&all_watches);
    notifyfs_id = vfs_regist(&notifyfs_fs);
}
