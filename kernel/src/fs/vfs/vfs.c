#include "fs/vfs/vfs.h"
#include "arch/arch.h"
#include "libs/hashmap.h"
#include "mm/mm.h"
#include "task/task.h"

struct llist_header vfs_nodes;
struct llist_header mount_points;
static hashmap_t vfs_inode_map = HASHMAP_INIT;
vfs_node_t rootdir = NULL;

fs_t *all_fs[256] = {
    [0] = NULL,
};

static int empty_func() { return -ENOSYS; }

static vfs_operations_t vfs_empty_ops;
int fs_nextid = 1;

void vfs_generic_free_handle(vfs_node_t node) {
    if (!node || !node->handle)
        return;
    free(node->handle);
}

static inline const vfs_operations_t *vfs_ops_of(vfs_node_t node) {
    if (!node)
        return &vfs_empty_ops;
    fs_t *fs = all_fs[node->fsid];
    if (!fs || !fs->ops)
        return &vfs_empty_ops;
    return fs->ops;
}

typedef struct vfs_child_bucket {
    uint64_t hash;
    size_t count;
    struct llist_header children;
} vfs_child_bucket_t;

static uint64_t vfs_name_hash(const char *name) {
    uint64_t hash = 1469598103934665603ULL;
    if (!name)
        return hash;

    while (*name) {
        hash ^= (uint8_t)*name++;
        hash *= 1099511628211ULL;
    }

    return hash;
}

static inline vfs_child_bucket_t *vfs_child_bucket_lookup(vfs_node_t parent,
                                                          uint64_t hash) {
    if (!parent)
        return NULL;
    return (vfs_child_bucket_t *)hashmap_get(&parent->child_name_map, hash);
}

static void vfs_child_index_deinit(vfs_node_t node) {
    if (!node || !node->child_name_map.buckets)
        return;

    for (size_t i = 0; i < node->child_name_map.bucket_count; i++) {
        hashmap_entry_t *entry = &node->child_name_map.buckets[i];
        if (!hashmap_entry_is_occupied(entry))
            continue;
        free(entry->value);
    }

    hashmap_deinit(&node->child_name_map);
}

static void vfs_child_index_add(vfs_node_t parent, vfs_node_t child) {
    if (!parent || !child || !child->name)
        return;

    uint64_t hash = vfs_name_hash(child->name);
    vfs_child_bucket_t *bucket = vfs_child_bucket_lookup(parent, hash);
    if (!bucket) {
        bucket = calloc(1, sizeof(vfs_child_bucket_t));
        if (!bucket)
            return;
        bucket->hash = hash;
        llist_init_head(&bucket->children);
        if (hashmap_put(&parent->child_name_map, hash, bucket) < 0) {
            free(bucket);
            return;
        }
    }

    llist_append(&bucket->children, &child->node_for_name_bucket);
    bucket->count++;
    child->child_name_hash = hash;
}

static void vfs_child_index_remove(vfs_node_t parent, vfs_node_t child) {
    if (!parent || !child || llist_empty(&child->node_for_name_bucket)) {
        if (child)
            child->child_name_hash = 0;
        return;
    }

    uint64_t hash = child->child_name_hash;
    vfs_child_bucket_t *bucket = vfs_child_bucket_lookup(parent, hash);
    llist_delete(&child->node_for_name_bucket);
    child->child_name_hash = 0;

    if (!bucket)
        return;

    if (bucket->count)
        bucket->count--;

    if (bucket->count == 0 || llist_empty(&bucket->children)) {
        hashmap_remove(&parent->child_name_map, hash);
        free(bucket);
    }
}

void vfs_detach_child(vfs_node_t node) {
    if (!node)
        return;
    vfs_node_t parent = node->parent;

    if (!parent)
        return;

    vfs_child_index_remove(parent, node);
    if (!llist_empty(&node->node_for_childs))
        llist_delete(&node->node_for_childs);
    node->child_name_hash = 0;
}

void vfs_attach_child(vfs_node_t parent, vfs_node_t child) {
    if (!parent || !child)
        return;

    child->parent = parent;
    if (llist_empty(&child->node_for_childs))
        llist_append(&parent->childs, &child->node_for_childs);
    if (llist_empty(&child->node_for_name_bucket))
        vfs_child_index_add(parent, child);
}

vfs_node_t vfs_node_alloc(vfs_node_t parent, const char *name) {
    vfs_node_t node = malloc(sizeof(struct vfs_node));
    if (node == NULL)
        return NULL;
    memset(node, 0, sizeof(struct vfs_node));
    node->parent = parent;
    node->flags = 0;
    node->dev = parent ? parent->dev : 0;
    node->rdev = parent ? parent->rdev : 0;
    node->blksz = DEFAULT_PAGE_SIZE;
    node->name = name ? strdup(name) : NULL;
    node->inode = alloc_fake_inode();
    node->type = file_none;
    node->fsid = parent ? parent->fsid : 0;
    node->root = parent ? parent->root : node;
    node->flock_lock.l_pid = 0;
    node->flock_lock.l_type = F_UNLCK;
    spin_init(&node->file_locks_lock);
    llist_init_head(&node->file_locks);
    llist_init_head(&node->node);
    llist_init_head(&node->childs);
    hashmap_init(&node->child_name_map, 16);
    llist_init_head(&node->node_for_childs);
    llist_init_head(&node->node_for_name_bucket);
    node->refcount = 0;
    node->mode = 0777;
    node->rw_hint = 0;
    node->handle = NULL;
    node->i_version = 1;
    spin_init(&node->poll_waiters_lock);
    llist_init_head(&node->poll_waiters);

    int rc = hashmap_put(&vfs_inode_map, node->inode, node);
    if (rc < 0) {
        vfs_child_index_deinit(node);
        free(node->name);
        free(node);
        return NULL;
    }

    if (parent)
        vfs_attach_child(parent, node);
    llist_append(&vfs_nodes, &node->node);
    return node;
}

void vfs_free_handle(vfs_node_t node) {
    bool has_handle = false;

    if (!node)
        return;

    has_handle = node->handle != NULL;

    if (has_handle)
        vfs_ops_of(node)->free_handle(node);

    node->handle = NULL;
}

void vfs_free(vfs_node_t vfs) {
    if (vfs == NULL)
        return;
    vfs_node_t child, tmp;
    vfs_file_lock_t *lock, *lock_tmp;
    llist_for_each(child, tmp, &vfs->childs, node_for_childs) {
        vfs_free(child);
    }
    llist_for_each(lock, lock_tmp, &vfs->file_locks, node) {
        llist_delete(&lock->node);
        free(lock);
    }
    vfs_detach_child(vfs);
    llist_delete(&vfs->node);
    hashmap_remove(&vfs_inode_map, vfs->inode);
    vfs_child_index_deinit(vfs);
    vfs_free_handle(vfs);
    free(vfs->name);
    free(vfs);
}

void vfs_free_child(vfs_node_t vfs) {
    if (vfs == NULL)
        return;
    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &vfs->childs, node_for_childs) {
        vfs_free(child);
    }
}

void vfs_merge_nodes_to(vfs_node_t dest, vfs_node_t source) {
    if (dest == source)
        return;
    uint64_t nodes_count = 0;
    vfs_node_t node, tmp;
    llist_for_each(node, tmp, &source->childs, node_for_childs) {
        nodes_count++;
    }
    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    uint64_t idx = 0;
    llist_for_each(node, tmp, &source->childs, node_for_childs) {
        nodes[idx++] = node;
    }
    for (uint64_t i = 0; i < idx; i++) {
        vfs_detach_child(nodes[i]);
        vfs_attach_child(dest, nodes[i]);
    }
    free(nodes);
}

vfs_node_t vfs_get_real_node(vfs_node_t node) {
    if (!node)
        return NULL;
    if (!(node->type & file_symlink))
        return node;

    char target_path[512];
    memset(target_path, 0, sizeof(target_path));
    int len = vfs_readlink(node, target_path, sizeof(target_path));
    target_path[len] = '\0';
    vfs_node_t target_node =
        vfs_open_at(node->parent, (const char *)target_path, 0);

    return target_node ?: node;
}

static inline void do_open(vfs_node_t file) {
    if (!file)
        return;

    bool needs_open = false;
    bool always_open = false;
    bool needs_children_refresh = false;
    vfs_node_t parent = NULL;
    char name[FILENAME_MAX];

    memset(name, 0, sizeof(name));

    fs_t *fs = all_fs[file->fsid];
    always_open = fs && (fs->flags & FS_FLAGS_ALWAYS_OPEN);
    needs_children_refresh = !!((file->flags & VFS_NODE_FLAGS_DIRTY_CHILDREN) &&
                                (file->type & file_dir));

    needs_open = always_open || file->handle == NULL || needs_children_refresh;
    parent = file->parent;
    if (file->name)
        strncpy(name, file->name, sizeof(name) - 1);

    if (needs_open && parent) {
        vfs_ops_of(file)->open(parent, name, file);
    }

    bool opened = file->handle != NULL;

    if (opened) {
        vfs_ops_of(file)->stat(file);
        file->flags |= VFS_NODE_FLAGS_OPENED;
        file->flags &=
            ~(VFS_NODE_FLAGS_DIRTY_METADATA | VFS_NODE_FLAGS_DIRTY_CHILDREN);
    }
}

static inline bool do_need_update(vfs_node_t file) {
    if (!file)
        return false;

    uint64_t flags = 0;
    void *handle = NULL;

    fs_t *fs = all_fs[file->fsid];
    flags = file->flags;
    handle = file->handle;

    if (fs && (fs->flags & FS_FLAGS_ALWAYS_OPEN) &&
        !(flags & VFS_NODE_FLAGS_OPENED)) {
        return true;
    }

    if (flags &
        (VFS_NODE_FLAGS_DIRTY_METADATA | VFS_NODE_FLAGS_DIRTY_CHILDREN)) {
        return true;
    }

    if (handle == NULL) {
        return true;
    }

    return false;
}

static inline void do_update(vfs_node_t file) {
    if (do_need_update(file))
        do_open(file);
}

vfs_node_t vfs_child_find(vfs_node_t parent, const char *name) {
    if (!parent || !name)
        return NULL;

    uint64_t hash = vfs_name_hash(name);
    vfs_child_bucket_t *bucket = vfs_child_bucket_lookup(parent, hash);
    vfs_node_t child_node, tmp;

    if (bucket) {
        llist_for_each(child_node, tmp, &bucket->children,
                       node_for_name_bucket) {
            if (child_node->name && streq(child_node->name, name))
                return child_node;
        }
    }

    llist_for_each(child_node, tmp, &parent->childs, node_for_childs) {
        if (!child_node->name || !streq(child_node->name, name))
            continue;

        if (child_node->child_name_hash != hash &&
            !llist_empty(&child_node->node_for_name_bucket)) {
            vfs_child_index_remove(parent, child_node);
        }
        if (llist_empty(&child_node->node_for_name_bucket)) {
            vfs_child_index_add(parent, child_node);
        }
        return child_node;
    }

    return NULL;
}

vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle) {
    vfs_node_t exist = vfs_child_find(parent, name);
    if (exist)
        vfs_free(exist);
    vfs_node_t node = vfs_node_alloc(parent, name);
    if (node == NULL)
        return NULL;
    node->handle = handle;
    return node;
}

static void vfs_forget_cached_node(vfs_node_t node) {
    if (!node || node == rootdir)
        return;

    node->flags |= VFS_NODE_FLAGS_DELETED;
    vfs_detach_child(node);
    if (node->refcount <= 0) {
        vfs_free_handle(node);
        vfs_free(node);
    }
}

extern struct llist_header all_watches;
extern spinlock_t all_watches_lock;
extern bool notifyfs_initialized;

void vfs_on_new_event(vfs_node_t node, uint64_t mask) {
    if (!node)
        return;

    vfs_mark_dirty(node, VFS_NODE_FLAGS_DIRTY_METADATA);
    if (mask & (IN_CREATE | IN_DELETE | IN_MOVE)) {
        vfs_mark_dirty(node, VFS_NODE_FLAGS_DIRTY_CHILDREN);
    }
    vfs_poll_notify(node, EPOLLIN | EPOLLPRI);

    if (!notifyfs_initialized)
        return;

    spin_lock(&all_watches_lock);

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &all_watches, all_watches_node) {
        if (!(pos->mask & mask))
            continue;
        if (node != pos->watch_node)
            continue;

        struct vfs_notify_event *event =
            malloc(sizeof(struct vfs_notify_event));
        if (!event)
            continue;
        memset(event, 0, sizeof(struct vfs_notify_event));
        llist_init_head(&event->node);
        event->changed_node = node;
        event->mask = mask;
        spin_lock(&pos->events_lock);
        llist_append(&pos->events, &event->node);
        spin_unlock(&pos->events_lock);

        if (pos->owner && pos->owner->node) {
            vfs_poll_notify(pos->owner->node, EPOLLIN);
        }
    }

    spin_unlock(&all_watches_lock);
}

void vfs_mark_dirty(vfs_node_t node, uint64_t dirty_flags) {
    if (!node)
        return;

    node->flags |= dirty_flags;
    node->i_version++;
}

void vfs_poll_wait_init(vfs_poll_wait_t *wait, task_t *task, uint32_t events) {
    if (!wait)
        return;

    memset(wait, 0, sizeof(*wait));
    wait->task = task;
    wait->events = events;
    llist_init_head(&wait->node);
}

int vfs_poll_wait_arm(vfs_node_t node, vfs_poll_wait_t *wait) {
    if (!node || !wait || !wait->task)
        return -EINVAL;
    if (wait->armed)
        return 0;

    wait->watch_node = node;
    wait->revents = 0;

    spin_lock(&node->poll_waiters_lock);
    llist_append(&node->poll_waiters, &wait->node);
    wait->armed = true;
    vfs_node_ref_get(node);
    spin_unlock(&node->poll_waiters_lock);

    return 0;
}

void vfs_poll_wait_disarm(vfs_poll_wait_t *wait) {
    if (!wait || !wait->armed || !wait->watch_node)
        return;

    vfs_node_t node = wait->watch_node;

    spin_lock(&node->poll_waiters_lock);
    if (wait->armed) {
        llist_delete(&wait->node);
        wait->armed = false;
        vfs_node_ref_put(node, NULL);
    }
    spin_unlock(&node->poll_waiters_lock);

    wait->watch_node = NULL;
    llist_init_head(&wait->node);
}

#define VFS_POLL_WAIT_SLICE_NS 10000000ULL

int vfs_poll_wait_sleep(vfs_node_t node, vfs_poll_wait_t *wait,
                        int64_t timeout_ns, const char *reason) {
    if (!node || !wait || !wait->task)
        return -EINVAL;

    uint32_t want = wait->events | EPOLLERR | EPOLLHUP | EPOLLNVAL | EPOLLRDHUP;
    uint64_t deadline = UINT64_MAX;

    if (timeout_ns >= 0) {
        uint64_t now = nano_time();
        deadline = now + (uint64_t)timeout_ns;
        if (deadline < now)
            deadline = UINT64_MAX;
    }

    while (true) {
        if ((wait->revents & want))
            return EOK;
        uint32_t revents = (vfs_poll(node, want) & want);
        if (revents) {
            wait->revents |= revents;
            return EOK;
        }

        int64_t block_ns = (int64_t)VFS_POLL_WAIT_SLICE_NS;
        if (timeout_ns >= 0) {
            uint64_t now = nano_time();
            if (now >= deadline)
                return ETIMEDOUT;
            uint64_t remain = deadline - now;
            if (remain < (uint64_t)block_ns)
                block_ns = (int64_t)remain;
        }

        int ret = task_block(wait->task, TASK_BLOCKING, block_ns, reason);
        if (ret == EOK || ret == ETIMEDOUT)
            continue;
        return ret;
    }
}

void vfs_poll_notify(vfs_node_t node, uint32_t events) {
    if (!node || !events)
        return;

    spin_lock(&node->poll_waiters_lock);
    if (events & (EPOLLIN | EPOLLRDNORM | EPOLLRDBAND | EPOLLRDHUP))
        node->poll_seq_in++;
    if (events & (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND))
        node->poll_seq_out++;
    if (events & EPOLLPRI)
        node->poll_seq_pri++;

    vfs_poll_wait_t *wait, *tmp;
    llist_for_each(wait, tmp, &node->poll_waiters, node) {
        if (!wait->armed || !wait->task)
            continue;

        uint32_t ready = events & (wait->events | EPOLLERR | EPOLLHUP |
                                   EPOLLNVAL | EPOLLRDHUP);
        if (!ready)
            continue;

        wait->revents |= ready;
        task_unblock(wait->task, EOK);
    }
    spin_unlock(&node->poll_waiters_lock);
}

int vfs_mkdir(const char *name) {
    int ret = -ENOENT;

    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task ? current_task->cwd : rootdir;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = NULL;
    if (strstr(path, "/")) {
        int pathlen = strlen(path);
        filename = path + pathlen;
        if (*--filename == '/') {
            *filename = '\0';
        }

        while (*--filename != '/' && filename != path) {
        }

        while (*filename == '/')
            *filename++ = '\0';

        if (filename == path) {
            goto create;
        }
    } else {
        filename = path;
        goto create;
    }

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir)) {
                ret = -ENOTDIR;
                goto err;
            }
            current = parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
        do_update(current);
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            if (!new_current) {
                ret = -ENOMEM;
                goto err;
            }
            new_current->type = file_dir;
            ret = vfs_ops_of(current)->mkdir(current, buf, new_current);
            if (ret < 0) {
                vfs_free(new_current);
                goto err;
            }
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
    }

create:
    if (!strlen(filename)) {
        free(path);
        return 0;
    }

    if (!(current->type & file_dir)) {
        ret = -ENOTDIR;
        goto err;
    }
    do_update(current);
    if (vfs_child_find(current, filename)) {
        ret = -EEXIST;
        goto err;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    if (!node) {
        ret = -ENOMEM;
        goto err;
    }
    node->type = file_dir;
    ret = vfs_ops_of(current)->mkdir(current, filename, node);
    if (ret < 0) {
        vfs_free(node);
        goto err;
    }

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return ret;

err:
    free(path);
    return ret;
}

int vfs_mkfile(const char *name) {
    int ret = -ENOENT;
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task ? current_task->cwd : rootdir;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = NULL;
    if (strstr(path, "/")) {
        int pathlen = strlen(path);
        filename = path + pathlen;
        if (*--filename == '/') {
            *filename = '\0';
        }

        while (*--filename != '/' && filename != path) {
        }

        while (*filename == '/')
            *filename++ = '\0';

        if (filename == path) {
            goto create;
        }
    } else {
        filename = path;
        goto create;
    }

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir)) {
                ret = -ENOTDIR;
                goto err;
            }
            current = parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
        do_update(current);
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_child_append(current, buf, NULL);
            if (!new_current) {
                free(path);
                return -ENOMEM;
            }
            new_current->type = file_dir;
            int ret = vfs_ops_of(current)->mkdir(current, buf, new_current);
            if (ret < 0) {
                vfs_free(new_current);
                free(path);
                return ret;
            }
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
    }

create:
    if (!strlen(filename)) {
        free(path);
        return 0;
    }

    if (!(current->type & file_dir)) {
        free(path);
        return -ENOTDIR;
    }
    do_update(current);
    if (vfs_child_find(current, filename)) {
        free(path);
        return -EEXIST;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    if (!node) {
        free(path);
        return -ENOMEM;
    }
    node->type = file_none;
    ret = vfs_ops_of(current)->mkfile(current, filename, node);
    if (ret < 0) {
        vfs_free(node);
        free(path);
        return ret;
    }

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return ret;
}

/**
 *\brief 创建link文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
static int vfs_link_internal(const char *name, const char *target_name,
                             vfs_node_t target_node) {
    int ret = -ENOENT;
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task ? current_task->cwd : rootdir;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = NULL;
    if (strstr(path, "/")) {
        int pathlen = strlen(path);
        filename = path + pathlen;
        if (*--filename == '/') {
            *filename = '\0';
        }

        while (*--filename != '/' && filename != path) {
        }

        while (*filename == '/')
            *filename++ = '\0';

        if (filename == path) {
            goto create;
        }
    } else {
        filename = path;
        goto create;
    }

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir)) {
                ret = -ENOTDIR;
                goto err;
            }
            current = parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
        do_update(current);
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            if (!new_current) {
                free(path);
                return -ENOMEM;
            }
            new_current->type = file_dir;
            int ret = vfs_ops_of(current)->mkdir(current, buf, new_current);
            if (ret < 0) {
                vfs_free(new_current);
                free(path);
                return ret;
            }
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
    }

create:
    if (!strlen(filename)) {
        free(path);
        return 0;
    }

    if (!(current->type & file_dir)) {
        free(path);
        return -ENOTDIR;
    }
    do_update(current);
    if (vfs_child_find(current, filename)) {
        free(path);
        return -EEXIST;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    if (!node) {
        free(path);
        return -ENOMEM;
    }
    node->type = file_none;
    if (target_node) {
        ret = vfs_ops_of(current)->link_node(current, target_node, node);
    } else {
        ret = vfs_ops_of(current)->link(current, target_name, node);
    }
    if (ret < 0) {
        vfs_free(node);
        free(path);
        return ret;
    }

    free(path);
    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return ret;
}

int vfs_link(const char *name, const char *target_name) {
    return vfs_link_internal(name, target_name, NULL);
}

int vfs_link_existing(const char *name, vfs_node_t target) {
    if (!target)
        return -ENOENT;
    return vfs_link_internal(name, NULL, target);
}

/**
 *\brief 创建symlink文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_symlink(const char *name, const char *target_name) {
    int ret = -ENOENT;
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task ? current_task->cwd : rootdir;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = NULL;
    if (strstr(path, "/")) {
        int pathlen = strlen(path);
        filename = path + pathlen;
        if (*--filename == '/') {
            *filename = '\0';
        }

        while (*--filename != '/' && filename != path) {
        }

        while (*filename == '/')
            *filename++ = '\0';

        if (filename == path) {
            goto create;
        }
    } else {
        filename = path;
        goto create;
    }

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir)) {
                ret = -ENOTDIR;
                goto err;
            }
            current = parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
        do_update(current);
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            if (!new_current) {
                free(path);
                return -ENOMEM;
            }
            new_current->type = file_dir;
            int ret = vfs_ops_of(current)->mkdir(current, buf, new_current);
            if (ret < 0) {
                vfs_free(new_current);
                free(path);
                return ret;
            }
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
    }

create:
    if (!strlen(filename)) {
        free(path);
        return 0;
    }

    if (!(current->type & file_dir)) {
        free(path);
        return -ENOTDIR;
    }
    do_update(current);
    if (vfs_child_find(current, filename)) {
        free(path);
        return -EEXIST;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    if (!node) {
        free(path);
        return -ENOMEM;
    }
    node->type = file_symlink;
    ret = vfs_ops_of(current)->symlink(current, target_name, node);
    if (ret < 0) {
        vfs_free(node);
        free(path);
        return ret;
    }

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return ret;
}

int vfs_mknod(const char *name, uint16_t umode, int dev) {
    int ret = -ENOENT;
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task ? current_task->cwd : rootdir;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = NULL;
    if (strstr(path, "/")) {
        int pathlen = strlen(path);
        filename = path + pathlen;
        if (*--filename == '/') {
            *filename = '\0';
        }

        while (*--filename != '/' && filename != path) {
        }

        while (*filename == '/')
            *filename++ = '\0';

        if (filename == path) {
            goto create;
        }
    } else {
        filename = path;
        goto create;
    }

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir)) {
                ret = -ENOTDIR;
                goto err;
            }
            current = parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
        do_update(current);
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            if (!new_current) {
                free(path);
                return -ENOMEM;
            }
            new_current->type = file_dir;
            int ret = vfs_ops_of(current)->mkdir(current, buf, new_current);
            if (ret < 0) {
                vfs_free(new_current);
                free(path);
                return ret;
            }
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir)) {
            ret = -ENOTDIR;
            goto err;
        }
    }

create:
    if (!strlen(filename)) {
        free(path);
        return 0;
    }

    if (!(current->type & file_dir)) {
        free(path);
        return -ENOTDIR;
    }
    do_update(current);
    if (vfs_child_find(current, filename)) {
        free(path);
        return -EEXIST;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    if (!node) {
        free(path);
        return -ENOMEM;
    }
    int ftype = 0;
    switch (umode & S_IFMT) {
    case S_IFBLK:
        ftype = file_block;
        break;
    case S_IFCHR:
        ftype = file_stream;
        break;
    case S_IFIFO:
        ftype = file_fifo;
        break;
    case S_IFSOCK:
        ftype = file_socket;
        break;
    default:
        ftype = file_none;
        break;
    }
    node->type = ftype;
    node->dev = dev;
    node->rdev = dev;
    ret = vfs_ops_of(current)->mknod(current, filename, node, umode, dev);
    if (ret < 0) {
        vfs_free(node);
        free(path);
        return ret;
    }

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return ret;
}

int vfs_chmod(const char *path, uint16_t mode) {
    vfs_node_t node = vfs_open(path, 0);
    if (!node)
        return -ENOENT;
    int ret = vfs_ops_of(node)->chmod(node, mode);
    return ret;
}

int vfs_fchmod(fd_t *fd, uint16_t mode) {
    int ret = vfs_ops_of(fd->node)->chmod(fd->node, mode);
    return ret;
}

int vfs_chown(const char *path, uint64_t uid, uint64_t gid) { return 0; }

int vfs_regist(fs_t *fs) {
    if (!fs)
        return -1;
    if (fs->ops == NULL)
        return -1;

    vfs_operations_t *normalized = malloc(sizeof(vfs_operations_t));
    if (!normalized)
        return -ENOMEM;
    memcpy(normalized, fs->ops, sizeof(vfs_operations_t));

    for (size_t i = 0; i < sizeof(vfs_operations_t) / sizeof(void *); i++) {
        if (((void **)normalized)[i] == NULL) {
            ((void **)normalized)[i] = ((void **)&vfs_empty_ops)[i];
        }
    }

    fs->ops = normalized;

    int id = fs_nextid++;
    all_fs[id] = fs;
    return id;
}

extern vfs_node_t procfs_root;

vfs_node_t vfs_open_at(vfs_node_t start, const char *_path, uint64_t flags) {
    if (!start)
        return NULL;

    if (_path == NULL)
        return NULL;
    vfs_node_t current = start;
    char *path;
    if (_path[0] == '/') {
        if (_path[1] == '\0') {
            return rootdir;
        }
        current = rootdir;
        path = strdup(_path + 1);
    } else {
        path = strdup(_path);
    }

    char *save_ptr = path;

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
            if (current == rootdir)
                continue;
            vfs_node_t parent = current->parent;
            if (!parent || !(current->type & file_dir))
                goto err;
            current = parent;
            continue;
        }
        if (!(current->type & file_dir))
            goto err;
        do_update(current);
        current = vfs_child_find(current, buf);
        if (current == NULL)
            goto err;
        do_update(current);

        if (current->type & file_symlink) {
            vfs_node_t symlink_node = current;
            char target_path[512];
            int len = vfs_readlink(current, target_path, sizeof(target_path));
            target_path[len] = '\0';
            vfs_node_t target_node =
                vfs_open_at(current->parent, (const char *)target_path, 0);

            if (!target_node)
                goto done;

            vfs_node_t target = target_node;
            if (!target)
                goto err;

            uint32_t target_type = target->type;
            uint64_t target_dev = target->dev;
            uint64_t target_rdev = target->rdev;
            uint64_t target_size = target->size;
            uint64_t target_blksz = target->blksz;
            uint16_t target_mode = target->mode;

            if (target_type & file_dir)
                current->type |= file_dir;
            if ((target_type & file_block) || (target_type & file_stream)) {
                current->type |= target_type;
                current->dev = target_dev;
                current->rdev = target_rdev;
            }
            current->size = target_size;
            current->blksz = target_blksz;

            // current->fsid = target->fsid;
            // current->handle = target->handle;
            // current->root = target->root;
            current->mode = target_mode;
            uint64_t symlink_flags = symlink_node->flags;

            char *p = strdup(save_ptr);
            char *ptr = p;
            const char *buf = pathtok(&ptr);
            if (!buf) {
                if (flags & O_NOFOLLOW) {
                    free(p);
                    goto done;
                }
            }
            free(p);

            current = target;

            if (symlink_flags & VFS_NODE_FLAGS_FREE_AFTER_USE) {
                vfs_close(symlink_node);
            }
        }
    }

done:
    free(path);
    return current;

err:
    free(path);
    return NULL;
}

vfs_node_t vfs_open(const char *_path, uint64_t flags) {
    vfs_node_t node = NULL;

    if (current_task && current_task->cwd) {
        node = vfs_open_at(current_task->cwd, _path, flags);
    } else {
        node = vfs_open_at(rootdir, _path, flags);
    }

    return node;
}

vfs_node_t vfs_find_node_by_inode(uint64_t inode) {
    return (vfs_node_t)hashmap_get(&vfs_inode_map, inode);
}

void vfs_update(vfs_node_t node) { do_update(node); }

bool vfs_init() {
    llist_init_head(&vfs_nodes);
    llist_init_head(&mount_points);

    if (hashmap_init(&vfs_inode_map, 4096) < 0) {
        return false;
    }

    for (size_t i = 0; i < sizeof(vfs_operations_t) / sizeof(void *); i++) {
        ((void **)&vfs_empty_ops)[i] = &empty_func;
    }

    rootdir = vfs_node_alloc(NULL, NULL);
    rootdir->type = file_dir;

    return true;
}

int vfs_close(vfs_node_t node) {
    bool has_handle = false;

    if (node == NULL)
        return -1;
    if (node == rootdir)
        return 0;

    has_handle = node->handle != NULL;
    if (!has_handle)
        return 0;

    bool dropped_ref = false;
    int refs = vfs_node_ref_put(node, &dropped_ref);
    if (dropped_ref && refs == 0) {
        node->flags &= ~VFS_NODE_FLAGS_OPENED;
        has_handle = node->handle != NULL;

        if (!has_handle)
            return 0;

        bool real_close = vfs_ops_of(node)->close(node);
        if (real_close) {
            bool free_after_use = false;
            bool deleted = false;

            node->handle = NULL;
            free_after_use = !!(node->flags & VFS_NODE_FLAGS_FREE_AFTER_USE);
            deleted = !!(node->flags & VFS_NODE_FLAGS_DELETED);

            if (free_after_use) {
                vfs_free(node);
                return 0;
            }
            if (deleted) {
                vfs_free(node);
            }
        }
    }

    return 0;
}

int vfs_mount(uint64_t dev, vfs_node_t node, const char *type) {
    if (node == NULL)
        return -EINVAL;
    if (!(node->type & file_dir))
        return -ENOTDIR;
    int ret = 0;
    for (int i = 1; i < fs_nextid; i++) {
        if (!all_fs[i] || !all_fs[i]->ops)
            continue;
        if (!strcmp(all_fs[i]->name, type)) {
            vfs_node_t old_root = node->root;
            node->root = node;
            ret = all_fs[i]->ops->mount(dev, node);
            if (!ret) {
                return 0;
            } else {
                node->root = old_root;
                printk("Mount fs %s failed, ret = %d\n", type, ret);
                return ret;
            }
        }
    }
    return -ENOENT;
}

int vfs_remount(vfs_node_t old, vfs_node_t dir) {
    int ret = vfs_ops_of(old)->remount(old, dir);
    if (ret < 0) {
        return ret;
    }
    struct mount_point *target = NULL;
    struct mount_point *mnt, *tmp;
    llist_for_each(mnt, tmp, &mount_points, node) {
        if (mnt->dir == old) {
            target = mnt;
            break;
        }
    }
    if (!target)
        return -ENOENT;
    char *devname = strdup(target->devname);
    vfs_delete_mount_point_by_dir(old);
    vfs_add_mount_point(dir, devname);
    free(devname);
    return 0;
}

void vfs_add_mount_point(vfs_node_t dir, char *devname) {
    struct mount_point *mnt = malloc(sizeof(struct mount_point));
    mnt->fs = all_fs[dir->fsid];
    mnt->dir = dir;
    mnt->devname = strdup(devname);
    llist_init_head(&mnt->node);
    llist_prepend(&mount_points, &mnt->node);
}

void vfs_delete_mount_point_by_dir(vfs_node_t dir) {
    struct mount_point *target = NULL;
    struct mount_point *mnt, *tmp;
    llist_for_each(mnt, tmp, &mount_points, node) {
        if (mnt->dir == dir) {
            target = mnt;
            break;
        }
    }

    if (!target)
        return;

    llist_delete(&target->node);
    free(target->devname);
    free(target);
}

ssize_t vfs_read(vfs_node_t file, void *addr, size_t offset, size_t size) {
    fd_t fd;
    fd.node = file;
    fd.flags = 0;
    fd.offset = offset;
    return vfs_read_fd(&fd, addr, offset, size);
}

ssize_t vfs_read_fd(fd_t *fd, void *addr, size_t offset, size_t size) {
    do_update(fd->node);
    if (fd->node->type & file_dir)
        return -EISDIR;

    if (fd->node->type & file_symlink) {
        char linkpath[512];
        memset(linkpath, 0, sizeof(linkpath));
        ssize_t ret = vfs_readlink(fd->node, linkpath, sizeof(linkpath));
        if (ret < 0)
            return ret;

        vfs_node_t linknode =
            vfs_open_at(fd->node->parent, (const char *)linkpath, 0);
        if (!linknode)
            return -ENOENT;
        do_update(linknode);

        return vfs_read(linknode, addr, offset, size);
    }

    ssize_t ret = vfs_ops_of(fd->node)->read(fd, addr, offset, size);
    if (ret > 0) {
        vfs_mark_dirty(fd->node, VFS_NODE_FLAGS_DIRTY_METADATA);
    }
    return ret;
}

int vfs_readlink(vfs_node_t node, char *buf, size_t bufsize) {
    int ret = vfs_ops_of(node)->readlink(node, buf, 0, bufsize);
    return ret;
}

ssize_t vfs_write(vfs_node_t file, const void *addr, size_t offset,
                  size_t size) {
    fd_t fd;
    fd.node = file;
    fd.flags = 0;
    fd.offset = offset;
    return vfs_write_fd(&fd, addr, offset, size);
}

ssize_t vfs_write_fd(fd_t *fd, const void *addr, size_t offset, size_t size) {
    do_update(fd->node);
    if (fd->node->type & file_dir)
        return -EISDIR;

    if (fd->node->type & file_symlink) {
        char linkpath[512];
        memset(linkpath, 0, sizeof(linkpath));
        ssize_t ret = vfs_readlink(fd->node, linkpath, sizeof(linkpath));
        if (ret < 0)
            return ret;

        vfs_node_t linknode =
            vfs_open_at(fd->node->parent, (const char *)linkpath, 0);
        if (!linknode)
            return -ENOENT;
        do_update(linknode);

        return vfs_write(linknode, addr, offset, size);
    }

    uint64_t node_size = fd->node->size;
    if (offset > node_size) {
        size_t fill_bytes = offset - node_size;
        size_t written = 0;

        char *zero_page = alloc_frames_bytes(DEFAULT_PAGE_SIZE);
        if (!zero_page)
            return -ENOMEM;
        memset(zero_page, 0, DEFAULT_PAGE_SIZE);

        while (written < fill_bytes) {
            size_t chunk = MIN(DEFAULT_PAGE_SIZE, fill_bytes - written);
            size_t old_size = fd->node->size;
            size_t write_offset = old_size + written;

            ssize_t ret =
                vfs_ops_of(fd->node)->write(fd, zero_page, write_offset, chunk);

            if (ret < 0) {
                free_frames_bytes(zero_page, DEFAULT_PAGE_SIZE);
                return ret;
            }

            if (ret == 0) {
                free_frames_bytes(zero_page, DEFAULT_PAGE_SIZE);
                return -ENOSPC;
            }

            written += ret;
            if (old_size == fd->node->size) {
                fd->node->size += ret;
            }
        }

        free_frames_bytes(zero_page, DEFAULT_PAGE_SIZE);
    }

    ssize_t write_bytes = 0;
    write_bytes = vfs_ops_of(fd->node)->write(fd, addr, offset, size);
    if (write_bytes > 0) {
        fd->node->size = MAX(fd->node->size, offset + write_bytes);
        vfs_mark_dirty(fd->node, VFS_NODE_FLAGS_DIRTY_METADATA);
        vfs_poll_notify(fd->node, EPOLLIN | EPOLLOUT);
    }
    return write_bytes;
}

int vfs_unmount(const char *path) {
    vfs_node_t node = vfs_open(path, 0);
    if (node == NULL)
        return -ENOENT;
    if (!(node->type & file_dir))
        return -ENOTDIR;
    uint32_t fsid = 0;
    fsid = node->fsid;
    if (fsid == 0)
        return -EINVAL;
    // list_foreach(node->child, i) {
    //     vfs_node_t child = i->data;
    //     if (child == child->root) {
    //         char *child_path = vfs_get_fullpath(child);
    //         vfs_unmount((const char *)child_path);
    //         free(child_path);
    //     }
    // }
    vfs_ops_of(node)->unmount(node);
    vfs_delete_mount_point_by_dir(node);
    return 0;
}

int vfs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    do_update(node);

    return vfs_ops_of(node)->ioctl(node, cmd, arg);
}

int vfs_poll(vfs_node_t node, size_t event) {
    if (!node)
        return -EBADF;
    do_update(node);
    if (node->type & file_dir)
        return EPOLLNVAL;
    int ret = vfs_ops_of(node)->poll(node, event);
    return ret;
}

// 使用请记得free掉返回的buff
char *vfs_get_fullpath(vfs_node_t node) {
    if (node == NULL)
        return NULL;

    int inital = 32;
    vfs_node_t *nodes = (vfs_node_t *)malloc(sizeof(vfs_node_t) * inital);
    int count = 0;
    for (vfs_node_t cur = node; cur;) {
        if (count >= inital) {
            inital *= 2;
            nodes = (vfs_node_t *)realloc(
                (void *)nodes, (size_t)(sizeof(vfs_node_t) * inital));
        }
        nodes[count++] = cur;
        vfs_node_t parent = cur->parent;
        if (!parent || cur == parent)
            break;
        cur = parent;
    }

    size_t total_len = 1;
    for (int j = count - 1; j >= 0; j--) {
        size_t name_len = 0;

        if (nodes[j] != rootdir && nodes[j]->name)
            name_len = strlen(nodes[j]->name);

        if (nodes[j] == rootdir || !name_len)
            continue;
        total_len += name_len + 1;
    }

    char *buff = (char *)malloc(total_len + 1);
    if (!buff) {
        free(nodes);
        return NULL;
    }

    size_t cursor = 0;
    buff[cursor++] = '/';
    buff[cursor] = '\0';
    for (int j = count - 1; j >= 0; j--) {
        if (nodes[j] == rootdir)
            continue;

        size_t name_len = 0;

        if (nodes[j]->name) {
            name_len = strlen(nodes[j]->name);
            memcpy(buff + cursor, nodes[j]->name, name_len);
        }

        if (!name_len)
            continue;

        cursor += name_len;

        if (j != 0) {
            buff[cursor++] = '/';
        }
        buff[cursor] = '\0';
    }

    free(nodes);

    return buff;
}

int vfs_delete(vfs_node_t node) {
    if (node == rootdir)
        return -EOPNOTSUPP;
    int res = vfs_ops_of(node)->delete(node->parent, node);
    if (res < 0) {
        return res;
    }
    node->flags |= VFS_NODE_FLAGS_DELETED;
    vfs_detach_child(node);
    if (node->refcount <= 0) {
        vfs_free_handle(node);
        vfs_free(node);
    }

    return 0;
}

int vfs_rename(vfs_node_t node, const char *new) {
    if (!node || !new)
        return -EINVAL;

    char *path = strdup(new);
    if (!path)
        return -ENOMEM;

    size_t path_len = strlen(path);
    while (path_len > 1 && path[path_len - 1] == '/') {
        path[--path_len] = '\0';
    }

    char *filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;
    if (!*filename) {
        free(path);
        return -EINVAL;
    }

    char *new_name = strdup(filename);
    if (!new_name) {
        free(path);
        return -ENOMEM;
    }

    char parent_path[512];
    memset(parent_path, 0, sizeof(parent_path));
    if (filename != path) {
        size_t parent_len = (size_t)((filename - 1) - path);
        if (parent_len == 0) {
            strcpy(parent_path, "/");
        } else {
            if (parent_len >= sizeof(parent_path)) {
                free(new_name);
                free(path);
                return -ENAMETOOLONG;
            }
            memcpy(parent_path, path, parent_len);
        }
    } else {
        strcpy(parent_path, ".");
    }

    vfs_node_t replaced_node = vfs_open(new, O_NOFOLLOW);
    if (replaced_node == node)
        replaced_node = NULL;

    vfs_node_t old_parent = node->parent;
    vfs_node_t new_parent = vfs_open(parent_path, 0);
    if (!new_parent) {
        free(new_name);
        free(path);
        return -ENOENT;
    }

    if (new_parent == old_parent && node->name &&
        !strcmp(node->name, new_name)) {
        free(new_name);
        free(path);
        return 0;
    }

    if (replaced_node && replaced_node->inode == node->inode) {
        free(new_name);
        free(path);
        return 0;
    }

    int ret = vfs_ops_of(node)->rename(node, new);
    if (ret < 0) {
        free(new_name);
        free(path);
        return ret;
    }

    if (replaced_node)
        vfs_forget_cached_node(replaced_node);

    vfs_detach_child(node);
    node->parent = new_parent;
    char *old_name = node->name;
    node->name = new_name;
    free(old_name);
    if (new_parent)
        vfs_attach_child(new_parent, node);

    vfs_on_new_event(old_parent, IN_MOVE);
    if (new_parent != old_parent)
        vfs_on_new_event(new_parent, IN_MOVE);

    free(path);
    return ret;
}

fd_t *vfs_dup(fd_t *fd) {
    fd_t *new_fd = malloc(sizeof(fd_t));
    memset(new_fd, 0, sizeof(fd_t));
    vfs_node_t node = fd->node;
    vfs_node_ref_get(node);
    new_fd->node = node;
    new_fd->offset = fd->offset;
    new_fd->flags = fd->flags;
    new_fd->close_on_exec = fd->close_on_exec;

    return new_fd;
}

void vfs_resize(vfs_node_t node, uint64_t size) {
    if (!(node->type & file_none))
        return;
    vfs_ops_of(node)->resize(node, size);
    node->size = size;
}

void *vfs_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot,
              uint64_t flags, uint64_t offset) {
    return vfs_ops_of(fd->node)->map(fd, (void *)addr, offset, len, prot,
                                     flags);
}
