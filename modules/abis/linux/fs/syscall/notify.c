#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

extern int notifyfs_id;
extern spinlock_t all_watches_lock;
extern int watch_desc;
extern struct llist_header all_watches;

uint64_t sys_inotify_init1(uint64_t flags) {
    if (flags & ~(O_NONBLOCK | O_CLOEXEC))
        return (uint64_t)-EINVAL;

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->type = file_none;
    node->fsid = notifyfs_id;
    node->refcount++;
    node->size = 0;
    notifyfs_handle_t *handle = malloc(sizeof(notifyfs_handle_t));
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
        procfs_on_open_file(current_task, fd);

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

    vfs_node_t node = vfs_open(path, O_NOFOLLOW);
    if (!node)
        return (uint64_t)-ENOENT;
    node = vfs_get_real_node(node);
    if (!node)
        return (uint64_t)-ENOENT;

    node->refcount++;

    spin_lock(&all_watches_lock);

    notifyfs_watch_t *watch = malloc(sizeof(notifyfs_watch_t));
    if (!watch) {
        spin_unlock(&all_watches_lock);
        vfs_close(node);
        return (uint64_t)-ENOMEM;
    }
    watch->watch_node = node;
    watch->owner = handle;
    watch->wd = watch_desc++;
    watch->mask = mask;

    llist_init_head(&watch->node);
    llist_prepend(&handle->watches, &watch->node);

    spin_init(&watch->events_lock);
    llist_init_head(&watch->events);

    llist_init_head(&watch->all_watches_node);
    llist_prepend(&all_watches, &watch->all_watches_node);

    spin_unlock(&all_watches_lock);

    return watch->wd;
}

extern void notifyfs_free_watch(notifyfs_watch_t *watch);

uint64_t sys_inotify_rm_watch(uint64_t watchdesc, uint64_t mask) {
    spin_lock(&all_watches_lock);

    notifyfs_watch_t *watch = NULL;
    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &all_watches, all_watches_node) {
        if (pos->wd == watchdesc) {
            watch = pos;
            break;
        }
    }

    if (!watch) {
        spin_unlock(&all_watches_lock);
        return (uint64_t)-EBADF;
    }

    llist_delete(&watch->node);
    llist_delete(&watch->all_watches_node);
    spin_unlock(&all_watches_lock);
    notifyfs_free_watch(watch);

    return 0;
}
