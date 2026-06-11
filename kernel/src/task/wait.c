#include <task/wait.h>
#include <task/task.h>
#include <fs/vfs/fcntl.h>

static inline uint32_t wait_queue_expand_events(uint32_t events) {
    if (events & EPOLLIN)
        events |= EPOLLRDNORM;
    if (events & EPOLLRDNORM)
        events |= EPOLLIN;
    if (events & EPOLLOUT)
        events |= EPOLLWRNORM;
    if (events & EPOLLWRNORM)
        events |= EPOLLOUT;
    return events;
}

static inline bool wait_queue_events_match(uint32_t wanted, uint32_t signaled) {
    if (!wanted || !signaled)
        return true;

    signaled = wait_queue_expand_events(signaled);
    wanted = wait_queue_expand_events(wanted);

    if (signaled & (EPOLLERR | EPOLLHUP | EPOLLNVAL))
        return true;
    return (wanted & signaled) != 0;
}

void wait_queue_init(wait_queue_head_t *queue) {
    if (!queue)
        return;

    spin_init(&queue->lock);
    llist_init_head(&queue->entries);
}

void wait_queue_entry_init(wait_queue_entry_t *entry, task_t *task,
                           uint32_t events, wait_queue_wake_func_t wake,
                           void *private_data) {
    if (!entry)
        return;

    llist_init_head(&entry->node);
    entry->task = task;
    entry->events = events;
    entry->wake = wake;
    entry->private_data = private_data;
}

void wait_queue_add(wait_queue_head_t *queue, wait_queue_entry_t *entry) {
    if (!queue || !entry)
        return;

    spin_lock(&queue->lock);
    if (llist_empty(&entry->node))
        llist_append(&queue->entries, &entry->node);
    spin_unlock(&queue->lock);
}

void wait_queue_remove(wait_queue_head_t *queue, wait_queue_entry_t *entry) {
    if (!queue || !entry)
        return;

    spin_lock(&queue->lock);
    if (!llist_empty(&entry->node))
        llist_delete(&entry->node);
    spin_unlock(&queue->lock);
}

int wait_queue_wake_entry(wait_queue_entry_t *entry, uint32_t events,
                          int reason) {
    if (!entry || !wait_queue_events_match(entry->events, events))
        return 0;

    if (entry->wake)
        return entry->wake(entry, events, reason);

    if (!entry->task || entry->task->state == TASK_DIED)
        return 0;

    task_unblock(entry->task, reason);
    return 1;
}

int wait_queue_wake(wait_queue_head_t *queue, uint32_t events, int nr,
                    int reason) {
    task_t *wake_tasks[64] = {0};
    int woke = 0;

    if (!queue)
        return 0;

    bool process_callbacks = true;
    while (nr <= 0 || woke < nr) {
        int wake_count = 0;

        spin_lock(&queue->lock);
        struct llist_header *node = queue->entries.next;
        while (node != &queue->entries) {
            wait_queue_entry_t *entry =
                list_entry(node, wait_queue_entry_t, node);
            task_t *task;

            node = node->next;

            if (!wait_queue_events_match(entry->events, events))
                continue;

            if (entry->wake) {
                /*
                 * Custom wake users currently own their lifetime externally
                 * (epoll watch entries). Keep those callbacks under the queue
                 * lock until they grow an explicit refcount.
                 */
                if (process_callbacks && entry->wake(entry, events, reason)) {
                    woke++;
                    if (nr > 0 && woke >= nr)
                        break;
                }
                continue;
            }

            task = entry->task;
            if (!task || task->state == TASK_DIED)
                continue;
            if (task->state != TASK_BLOCKING &&
                task->state != TASK_UNINTERRUPTABLE && !task->block_preparing)
                continue;

            wake_tasks[wake_count++] = task;
            woke++;
            if (nr > 0 && woke >= nr)
                break;
            if (wake_count >= (int)(sizeof(wake_tasks) / sizeof(wake_tasks[0])))
                break;
        }
        spin_unlock(&queue->lock);

        for (int i = 0; i < wake_count; i++)
            task_unblock(wake_tasks[i], reason);

        process_callbacks = false;
        if (wake_count < (int)(sizeof(wake_tasks) / sizeof(wake_tasks[0])))
            break;
    }

    return woke;
}

int wait_queue_wake_all(wait_queue_head_t *queue, uint32_t events, int reason) {
    return wait_queue_wake(queue, events, 0, reason);
}
