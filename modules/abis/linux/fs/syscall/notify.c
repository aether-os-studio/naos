#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>
#include <init/callbacks.h>

extern int notifyfs_id;
extern spinlock_t all_watches_lock;
extern int watch_desc;
extern struct llist_header all_watches;

static const uint64_t inotify_valid_user_mask = IN_ALL_EVENTS | IN_DONT_FOLLOW |
                                                IN_EXCL_UNLINK | IN_MASK_ADD |
                                                IN_ONESHOT | IN_ONLYDIR;
static const uint64_t inotify_stored_watch_mask =
    IN_ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT;

static notifyfs_watch_t *
notifyfs_find_watch_by_node_locked(notifyfs_handle_t *handle, vfs_node_t *node,
                                   bool active_only) {
    if (!handle || !node)
        return NULL;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        if (pos->watch_node != node)
            continue;
        if (active_only && !pos->active)
            continue;
        return pos;
    }

    return NULL;
}

static notifyfs_watch_t *
notifyfs_find_watch_by_wd_locked(notifyfs_handle_t *handle, uint64_t wd,
                                 bool active_only) {
    if (!handle)
        return NULL;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        if (pos->wd != wd)
            continue;
        if (active_only && !pos->active)
            continue;
        return pos;
    }

    return NULL;
}

uint64_t sys_inotify_init1(uint64_t flags) {
    if (flags & ~(O_NONBLOCK | O_CLOEXEC))
        return (uint64_t)-EINVAL;

    vfs_node_t *node = vfs_node_alloc(NULL, NULL);
    node->type = file_stream;
    node->fsid = notifyfs_id;
    node->refcount++;
    node->size = 0;
    notifyfs_handle_t *handle = calloc(1, sizeof(notifyfs_handle_t));
    if (!handle) {
        vfs_free(node);
        return (uint64_t)-ENOMEM;
    }
    node->handle = handle;
    handle->node = node;
    llist_init_head(&handle->watches);

    int fd = -1;
    int ret = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (!current_task->fd_info->fds[i]) {
                fd = i;
                break;
            }
        }

        if (fd < 0)
            break;

        fd_t *new_fd = fd_create(node, O_RDONLY | (flags & O_NONBLOCK),
                                 !!(flags & O_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        current_task->fd_info->fds[fd] = new_fd;
        on_open_file_call(current_task, fd);

        ret = 0;
    });

    if (ret < 0) {
        vfs_free(node);
        return (uint64_t)ret;
    }

    return fd;
}

uint64_t sys_inotify_init() { return sys_inotify_init1(0); }

uint64_t sys_inotify_add_watch(uint64_t notifyfd, const char *path_user,
                               uint64_t mask) {
    if (mask & ~inotify_valid_user_mask)
        return (uint64_t)-EINVAL;

    if (notifyfd >= MAX_FD_NUM ||
        current_task->fd_info->fds[notifyfd] == NULL) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t *notify_node = current_task->fd_info->fds[notifyfd]->node;
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

    uint64_t open_flags = (mask & IN_DONT_FOLLOW) ? O_NOFOLLOW : 0;
    vfs_node_t *node = vfs_open(path, open_flags);
    if (!node)
        return (uint64_t)-ENOENT;
    if (!(mask & IN_DONT_FOLLOW)) {
        node = vfs_get_real_node(node);
        if (!node)
            return (uint64_t)-ENOENT;
    }

    if ((mask & IN_ONLYDIR) && !(node->type & file_dir)) {
        vfs_close(node);
        return (uint64_t)-ENOTDIR;
    }

    node->refcount++;

    spin_lock(&all_watches_lock);

    uint64_t effective_mask = mask & inotify_stored_watch_mask;
    notifyfs_watch_t *existing =
        notifyfs_find_watch_by_node_locked(handle, node, true);
    if (existing) {
        if (mask & IN_MASK_ADD) {
            existing->mask |= effective_mask;
        } else {
            existing->mask = effective_mask;
        }
        spin_unlock(&all_watches_lock);
        vfs_close(node);
        return existing->wd;
    }

    notifyfs_watch_t *watch = malloc(sizeof(notifyfs_watch_t));
    if (!watch) {
        spin_unlock(&all_watches_lock);
        vfs_close(node);
        return (uint64_t)-ENOMEM;
    }
    watch->watch_node = node;
    watch->owner = handle;
    watch->wd = watch_desc++;
    watch->mask = effective_mask;
    watch->active = true;

    llist_init_head(&watch->node);
    llist_prepend(&handle->watches, &watch->node);

    spin_init(&watch->events_lock);
    llist_init_head(&watch->events);

    llist_init_head(&watch->all_watches_node);
    llist_prepend(&all_watches, &watch->all_watches_node);

    spin_unlock(&all_watches_lock);

    return watch->wd;
}

uint64_t sys_inotify_rm_watch(uint64_t notifyfd, uint64_t watchdesc) {
    if (notifyfd >= MAX_FD_NUM || !current_task->fd_info->fds[notifyfd]) {
        return (uint64_t)-EBADF;
    }

    vfs_node_t *notify_node = current_task->fd_info->fds[notifyfd]->node;
    if (!notify_node || notify_node->fsid != notifyfs_id) {
        return (uint64_t)-EINVAL;
    }

    notifyfs_handle_t *handle = notify_node->handle;
    if (!handle) {
        return (uint64_t)-EINVAL;
    }

    spin_lock(&all_watches_lock);

    notifyfs_watch_t *watch =
        notifyfs_find_watch_by_wd_locked(handle, watchdesc, true);
    if (!watch) {
        spin_unlock(&all_watches_lock);
        return (uint64_t)-EINVAL;
    }

    notifyfs_watch_deactivate_locked(watch, true);
    spin_unlock(&all_watches_lock);

    return 0;
}
