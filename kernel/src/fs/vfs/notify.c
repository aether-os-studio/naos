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

static size_t notify_event_name_len(const struct vfs_notify_event *event) {
    if (!event || !event->name_len)
        return 0;

    size_t len = (size_t)event->name_len + 1;
    return (len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
}

static struct vfs_notify_event *
notifyfs_event_alloc(const char *name, uint64_t mask, uint32_t cookie) {
    struct vfs_notify_event *event = calloc(1, sizeof(*event));
    if (!event)
        return NULL;

    llist_init_head(&event->node);
    event->mask = mask;
    event->cookie = cookie;

    if (name && name[0]) {
        size_t name_len = strlen(name);
        if (name_len > UINT32_MAX) {
            free(event);
            return NULL;
        }

        event->name = strdup(name);
        if (!event->name) {
            free(event);
            return NULL;
        }
        event->name_len = (uint32_t)name_len;
    }

    return event;
}

static void notifyfs_event_free(struct vfs_notify_event *event) {
    if (!event)
        return;

    free(event->name);
    free(event);
}

static void notifyfs_signal_owner(notifyfs_watch_t *watch) {
    if (!watch || !watch->owner || !watch->owner->node)
        return;

    vfs_poll_notify(watch->owner->node, EPOLLIN);
}

void notifyfs_watch_deactivate_locked(notifyfs_watch_t *watch,
                                      bool queue_ignored) {
    if (!watch || !watch->active)
        return;

    if (!llist_empty(&watch->all_watches_node)) {
        llist_delete(&watch->all_watches_node);
        llist_init_head(&watch->all_watches_node);
    }
    watch->active = false;

    if (!queue_ignored)
        return;

    struct vfs_notify_event *event = notifyfs_event_alloc(NULL, IN_IGNORED, 0);
    if (!event)
        return;

    spin_lock(&watch->events_lock);
    llist_append(&watch->events, &event->node);
    spin_unlock(&watch->events_lock);

    notifyfs_signal_owner(watch);
}

bool notifyfs_watch_queue_event_locked(notifyfs_watch_t *watch,
                                       vfs_node_t *changed_node,
                                       const char *name, uint64_t mask,
                                       uint32_t cookie) {
    if (!watch)
        return false;

    uint64_t event_mask = mask;
    if (changed_node && (changed_node->type & file_dir))
        event_mask |= IN_ISDIR;

    const char *event_name = name;
    if (!event_name && changed_node && changed_node != watch->watch_node &&
        changed_node->name && changed_node->name[0]) {
        event_name = changed_node->name;
    }

    struct vfs_notify_event *event =
        notifyfs_event_alloc(event_name, event_mask, cookie);
    if (!event)
        return false;

    spin_lock(&watch->events_lock);
    llist_append(&watch->events, &event->node);
    spin_unlock(&watch->events_lock);

    notifyfs_signal_owner(watch);

    if (watch->mask & IN_ONESHOT) {
        notifyfs_watch_deactivate_locked(watch, true);
    }

    return true;
}

static bool notifyfs_watch_has_events_locked(notifyfs_watch_t *watch) {
    if (!watch)
        return false;

    bool has_events = false;
    spin_lock(&watch->events_lock);
    has_events = !llist_empty(&watch->events);
    spin_unlock(&watch->events_lock);
    return has_events;
}

static void
notifyfs_maybe_collect_stale_watch_locked(notifyfs_watch_t *watch,
                                          struct llist_header *stale) {
    if (!watch || watch->active)
        return;

    bool has_events = notifyfs_watch_has_events_locked(watch);
    if (has_events || llist_empty(&watch->node))
        return;

    llist_delete(&watch->node);
    if (stale)
        llist_append(stale, &watch->node);
}

bool notifyfs_handle_has_events_locked(notifyfs_handle_t *handle) {
    if (!handle)
        return false;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &handle->watches, node) {
        if (notifyfs_watch_has_events_locked(pos))
            return true;
    }

    return false;
}

void notifyfs_free_watch(notifyfs_watch_t *watch);

static void notifyfs_free_watch_list(struct llist_header *stale_watches) {
    if (!stale_watches)
        return;

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, stale_watches, node) {
        llist_delete(&pos->node);
        notifyfs_free_watch(pos);
    }
}

ssize_t notifyfs_drain_events_locked(notifyfs_handle_t *handle, void *addr,
                                     size_t size,
                                     struct llist_header *stale_watches) {
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
                if (total_write == 0)
                    return -EINVAL;
                goto out;
            }

            llist_delete(&p->node);
            struct inotify_event *event = (struct inotify_event *)write_pos;
            memset(event, 0, tot_len);
            event->wd = (int)pos->wd;
            event->mask = (unsigned int)p->mask;
            event->cookie = p->cookie;
            event->len = (unsigned int)name_len;
            if (name_len > 0 && p->name) {
                memcpy(event->name, p->name, p->name_len);
            }
            total_write += tot_len;
            write_pos += tot_len;
            notifyfs_event_free(p);
        }
        spin_unlock(&pos->events_lock);

        notifyfs_maybe_collect_stale_watch_locked(pos, stale_watches);
    }

out:
    return (ssize_t)total_write;
}

void notifyfs_free_watch(notifyfs_watch_t *watch) {
    if (!watch)
        return;

    if (!llist_empty(&watch->all_watches_node)) {
        llist_delete(&watch->all_watches_node);
        llist_init_head(&watch->all_watches_node);
    }

    spin_lock(&watch->events_lock);
    struct vfs_notify_event *p, *t;
    llist_for_each(p, t, &watch->events, node) {
        llist_delete(&p->node);
        notifyfs_event_free(p);
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
        if (watch->active) {
            notifyfs_watch_deactivate_locked(watch, false);
        }
        llist_append(&stale_watches, &watch->node);
    }
    spin_unlock(&all_watches_lock);

    notifyfs_free_watch_list(&stale_watches);

    free(handle);
}

ssize_t notifyfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    notifyfs_handle_t *handle = fd->node->handle;
    if (!handle)
        return -EINVAL;

    while (true) {
        struct llist_header stale_watches;
        llist_init_head(&stale_watches);

        spin_lock(&all_watches_lock);
        ssize_t ret =
            notifyfs_drain_events_locked(handle, addr, size, &stale_watches);
        spin_unlock(&all_watches_lock);
        notifyfs_free_watch_list(&stale_watches);
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
    node->handle = NULL;
    notifyfs_destroy_handle(handle);
    return true;
}

void notifyfs_free_handle(vfs_node_t *node) {
    notifyfs_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return;
    node->handle = NULL;
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
    .flags = FS_FLAGS_VIRTUAL | FS_FLAGS_HIDDEN,
};

bool notifyfs_initialized = false;

void notifyfs_init() {
    notifyfs_id = vfs_regist(&notifyfs_fs);
    notifyfs_initialized = true;
}
