#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

int notifyfs_id = 0;
int watch_desc = 1;
DEFINE_LLIST(all_watches);
spinlock_t all_watches_lock = SPIN_INIT;

struct inotify_event {
    int wd;
    unsigned int mask;
    unsigned int cookie;
    unsigned int len;
    char name[];
};

size_t notify_event_name_len(const struct vfs_notify_event *event) {
    if (!event || !event->changed_node || !event->changed_node->name)
        return 0;

    return strlen(event->changed_node->name) + 1;
}

bool notifyfs_handle_has_events_locked(notifyfs_handle_t *handle) {
    if (!handle)
        return false;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        bool has_events = false;
        spin_lock(&pos->events_lock);
        has_events = !llist_empty(&pos->events);
        spin_unlock(&pos->events_lock);
        if (has_events)
            return true;
    }

    return false;
}

ssize_t notifyfs_drain_events_locked(notifyfs_handle_t *handle, void *addr,
                                     size_t size) {
    uint64_t total_write = 0;
    uint8_t *write_pos = (uint8_t *)addr;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        spin_lock(&pos->events_lock);
        struct vfs_notify_event *p, *t;
        llist_for_each(p, t, &pos->events, node) {
            size_t name_len = notify_event_name_len(p);
            size_t tot_len = sizeof(struct inotify_event) + name_len;
            if (total_write + tot_len > size) {
                spin_unlock(&pos->events_lock);
                return total_write ? (ssize_t)total_write : -EINVAL;
            }

            llist_delete(&p->node);
            struct inotify_event *event = (struct inotify_event *)write_pos;
            event->wd = pos->wd;
            event->mask = p->mask;
            event->cookie = 0;
            event->len = (unsigned int)name_len;
            if (name_len > 0) {
                memcpy(event->name, p->changed_node->name, name_len);
            }
            total_write += tot_len;
            write_pos += tot_len;
            free(p);
        }
        spin_unlock(&pos->events_lock);
    }

    return (ssize_t)total_write;
}

void notifyfs_free_watch(notifyfs_watch_t *watch) {
    if (!watch)
        return;

    spin_lock(&watch->events_lock);
    struct vfs_notify_event *p, *t;
    llist_for_each(p, t, &watch->events, node) {
        llist_delete(&p->node);
        free(p);
    }
    spin_unlock(&watch->events_lock);

    vfs_close(watch->watch_node);
    free(watch);
}

void notifyfs_destroy_handle(notifyfs_handle_t *handle) {
    if (!handle)
        return;

    struct llist_header stale_watches;
    llist_init_head(&stale_watches);

    spin_lock(&all_watches_lock);
    while (!llist_empty(&handle->watches)) {
        notifyfs_watch_t *watch =
            list_entry(handle->watches.next, notifyfs_watch_t, node);
        llist_delete(&watch->node);
        llist_delete(&watch->all_watches_node);
        llist_append(&stale_watches, &watch->node);
    }
    spin_unlock(&all_watches_lock);

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &stale_watches, node) {
        llist_delete(&pos->node);
        notifyfs_free_watch(pos);
    }

    free(handle);
}

ssize_t notifyfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    notifyfs_handle_t *handle = fd->node->handle;
    if (!handle)
        return -EINVAL;

    while (true) {
        spin_lock(&all_watches_lock);
        ssize_t ret = notifyfs_drain_events_locked(handle, addr, size);
        spin_unlock(&all_watches_lock);
        if (ret != 0)
            return ret;

        if (fd_get_flags(fd) & O_NONBLOCK)
            return -EWOULDBLOCK;

        vfs_poll_wait_t wait;
        vfs_poll_wait_init(&wait, current_task, EPOLLIN | EPOLLERR | EPOLLHUP);
        vfs_poll_wait_arm(fd->node, &wait);

        spin_lock(&all_watches_lock);
        bool has_events = notifyfs_handle_has_events_locked(handle);
        spin_unlock(&all_watches_lock);

        if (!has_events) {
            int reason =
                vfs_poll_wait_sleep(fd->node, &wait, -1, "notifyfs_read");
            vfs_poll_wait_disarm(&wait);
            if (reason != EOK)
                return -EINTR;
        } else {
            vfs_poll_wait_disarm(&wait);
        }
    }
}

int notifyfs_ioctl(fd_t *fd, ssize_t cmd, ssize_t arg) {
    vfs_node_t *node = fd->node;
    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return -EINVAL;

    switch (cmd) {
    case FIONREAD: {
        int total = 0;
        spin_lock(&all_watches_lock);
        notifyfs_watch_t *pos, *tmp;
        llist_for_each(pos, tmp, &handle->watches, node) {
            spin_lock(&pos->events_lock);
            struct vfs_notify_event *p, *t;
            llist_for_each(p, t, &pos->events, node) {
                total +=
                    sizeof(struct inotify_event) + notify_event_name_len(p);
            }
            spin_unlock(&pos->events_lock);
        }
        spin_unlock(&all_watches_lock);

        if (copy_to_user((void *)arg, &total, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    default:
        return -EINVAL;
    }
}

int notifyfs_poll(vfs_node_t *node, size_t events) {
    int revents = 0;

    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return EPOLLNVAL;
    if (events & EPOLLIN) {
        spin_lock(&all_watches_lock);
        if (notifyfs_handle_has_events_locked(handle))
            revents |= EPOLLIN;
        spin_unlock(&all_watches_lock);
    }

    return revents;
}

bool notifyfs_close(vfs_node_t *node) {
    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return true;
    node->flags |= VFS_NODE_FLAGS_DELETED;
    notifyfs_destroy_handle(handle);
    return true;
}

void notifyfs_free_handle(vfs_node_t *node) {
    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;
    notifyfs_destroy_handle(handle);
}

static vfs_operations_t notifyfs_callbacks = {
    .close = notifyfs_close,
    .read = notifyfs_read,
    .poll = notifyfs_poll,
    .ioctl = notifyfs_ioctl,

    .free_handle = notifyfs_free_handle,
};

fs_t notifyfs_fs = {
    .name = "notifyfs",
    .magic = 0,
    .ops = &notifyfs_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

bool notifyfs_initialized = false;

void notifyfs_init() {
    notifyfs_id = vfs_regist(&notifyfs_fs);
    notifyfs_initialized = true;
}
