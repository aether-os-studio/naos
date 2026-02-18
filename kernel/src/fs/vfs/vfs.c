#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/fs_syscall.h"
#include "arch/arch.h"
#include "mm/mm.h"
#include "task/task.h"
#include "net/socket.h"
#include "drivers/pty.h"

struct llist_header vfs_nodes;
struct llist_header mount_points;
vfs_node_t rootdir = NULL;

fs_t *all_fs[256] = {
    [0] = NULL,
};

static int empty_func() { return -ENOSYS; }

static struct vfs_callback vfs_empty_callback;

vfs_callback_t fs_callbacks[256] = {
    [0] = &vfs_empty_callback,
};
int fs_nextid = 1;

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
    node->lock.l_pid = 0;
    node->lock.l_type = F_UNLCK;
    llist_init_head(&node->node);
    llist_init_head(&node->childs);
    llist_init_head(&node->node_for_childs);
    node->refcount = 0;
    node->mode = 0777;
    node->rw_hint = 0;
    node->handle = NULL;
    if (parent)
        llist_append(&parent->childs, &node->node_for_childs);
    llist_append(&vfs_nodes, &node->node);
    return node;
}

void vfs_free_handle(vfs_node_t node) {
    if (node->handle)
        callbackof(node, free_handle)(node->handle);
    node->handle = NULL;
}

void vfs_free(vfs_node_t vfs) {
    if (vfs == NULL)
        return;
    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &vfs->childs, node_for_childs) {
        vfs_free(child);
    }
    llist_delete(&vfs->node_for_childs);
    llist_delete(&vfs->node);
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
        llist_delete(&nodes[i]->node_for_childs);
        nodes[i]->parent = dest;
        llist_append(&dest->childs, &nodes[i]->node_for_childs);
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
    if (file->handle != NULL) {
        callbackof(file, stat)(file->handle, file);
    } else if (file->parent) {
        callbackof(file, open)(file->parent->handle, file->name, file);
    }
}

static inline void do_update(vfs_node_t file) {
    if (file->handle == NULL)
        do_open(file);
}

vfs_node_t vfs_child_find(vfs_node_t parent, const char *name) {
    if (!parent || !name)
        return NULL;
    vfs_node_t child_node, tmp;
    llist_for_each(child_node, tmp, &parent->childs, node_for_childs) {
        if (child_node->name && streq(child_node->name, name))
            return child_node;
    }
    return NULL;
}

// 一定要记得手动设置一下child的type
vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle) {
    vfs_node_t node = vfs_child_find(parent, name);
    if (node) {
        if (node != node->root) {
            node->dev = parent->dev;
            node->rdev = parent->rdev;
        }
        return node;
    }
    node = vfs_node_alloc(parent, name);
    if (node == NULL)
        return NULL;
    node->handle = handle;
    return node;
}

extern struct llist_header all_watches;
extern spinlock_t all_watches_lock;
extern bool notifyfs_initialized;

void vfs_on_new_event(vfs_node_t node, uint64_t mask) {
    if (!notifyfs_initialized)
        return;

    spin_lock(&all_watches_lock);

    notifyfs_watch_t *pos, *tmp;
    llist_for_each(pos, tmp, &all_watches, all_watches_node) {
        if (pos->mask & mask) {
            if (node != pos->watch_node) {
                goto ret;
            }
            struct vfs_notify_event *event =
                malloc(sizeof(struct vfs_notify_event));
            memset(event, 0, sizeof(struct vfs_notify_event));
            llist_init_head(&event->node);
            event->changed_node = node;
            event->mask = mask;
            spin_lock(&pos->events_lock);
            llist_append(&pos->events, &event->node);
            spin_unlock(&pos->events_lock);
        }
    }

ret:
    spin_unlock(&all_watches_lock);
}

int vfs_mkdir(const char *name) {
    int ret = 0;

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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    if (!strlen(filename))
        return 0;

    if (vfs_child_find(current, filename)) {
        ret = -EEXIST;
        goto err;
    }

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_dir;
    callbackof(current, mkdir)(current->handle, filename, node);

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return ret;

err:
    free(path);
    return ret;
}

int vfs_mkfile(const char *name) {
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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_child_append(current, buf, NULL);
            new_current->type = file_dir;
            int ret =
                callbackof(current, mkdir)(current->handle, buf, new_current);
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_none;
    callbackof(current, mkfile)(current->handle, filename, node);

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return -1;
}

/**
 *\brief 创建link文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_link(const char *name, const char *target_name) {
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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    if (!strlen(filename))
        return 0;

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_none;
    callbackof(current, link)(current->handle, target_name, node);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return -1;
}

/**
 *\brief 创建symlink文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_symlink(const char *name, const char *target_name) {
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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    if (!strlen(filename))
        return 0;

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_symlink;
    ssize_t ret =
        callbackof(current, symlink)(current->handle, target_name, node);
    if (ret < 0) {
        free(path);
        return ret;
    }

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return -EIO;
}

int vfs_mknod(const char *name, uint16_t umode, int dev) {
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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL) {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
            vfs_on_new_event(current, IN_CREATE);
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    if (!strlen(filename))
        return 0;

    vfs_node_t node = vfs_child_append(current, filename, NULL);
    int ftype = 0;
    switch (umode & S_IFMT) {
    case S_IFBLK:
        node->type = file_block;
        break;
    case S_IFCHR:
        node->type = file_stream;
        break;
    case S_IFIFO:
        node->type = file_fifo;
        break;
    default:
        node->type = file_none;
        break;
    }
    node->dev = dev;
    node->rdev = dev;
    callbackof(current, mknod)(current->handle, filename, node, umode, dev);

    free(path);

    vfs_on_new_event(current, IN_CREATE);

    return 0;

err:
    free(path);
    return -1;
}

int vfs_chmod(const char *path, uint16_t mode) {
    vfs_node_t node = vfs_open(path, 0);
    if (!node)
        return -ENOENT;
    int ret = callbackof(node, chmod)(node, mode);
    return ret;
}

int vfs_fchmod(fd_t *fd, uint16_t mode) {
    int ret = callbackof(fd->node, chmod)(fd->node, mode);
    return ret;
}

int vfs_chown(const char *path, uint64_t uid, uint64_t gid) { return 0; }

int vfs_regist(fs_t *fs) {
    vfs_callback_t callback = fs->callback;

    if (callback == NULL)
        return -1;
    for (size_t i = 0; i < sizeof(struct vfs_callback) / sizeof(void *); i++) {
        if (((void **)callback)[i] == NULL)
            return -1;
    }
    int id = fs_nextid++;
    fs_callbacks[id] = callback;
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
            if (!current->parent || !(current->type & file_dir))
                goto err;
            current = current->parent;
            continue;
        }
        if (!(current->type & file_dir)) {
            goto err;
        }
        vfs_node_t free_node = NULL;
        if (current->flags & VFS_NODE_FLAGS_FREE_AFTER_USE) {
            free_node = current;
        }
        current = vfs_child_find(current, buf);
        if (free_node) {
            free(free_node->name);
            free(free_node);
        }
        if (current == NULL)
            goto err;
        fs_t *fs = all_fs[current->fsid];
        if (fs && (fs->flags & FS_FLAGS_NEED_OPEN) &&
            !(current->flags & VFS_NODE_FLAGS_OPENED)) {
            callbackof(current, open)(current->parent->handle, current->name,
                                      current);
            current->flags |= VFS_NODE_FLAGS_OPENED;
        } else {
            do_update(current);
        }

        if (current->type & file_symlink) {
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

            if (target->type & file_dir)
                current->type |= file_dir;
            if ((target->type & file_block) || (target->type & file_stream)) {
                current->type |= target->type;
                current->dev = target->dev;
                current->rdev = target->rdev;
            }
            current->size = target->size;
            current->blksz = target->blksz;

            // current->fsid = target->fsid;
            // current->handle = target->handle;
            // current->root = target->root;
            current->mode = target->mode;

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
    vfs_node_t pos, tmp;
    llist_for_each(pos, tmp, &vfs_nodes, node) {
        if (pos->inode == inode)
            return pos;
    }
    return NULL;
}

void vfs_update(vfs_node_t node) { do_update(node); }

bool vfs_init() {
    llist_init_head(&vfs_nodes);
    llist_init_head(&mount_points);

    for (size_t i = 0; i < sizeof(struct vfs_callback) / sizeof(void *); i++) {
        ((void **)&vfs_empty_callback)[i] = &empty_func;
    }

    rootdir = vfs_node_alloc(NULL, NULL);
    rootdir->type = file_dir;
    rootdir->fsid = 0;

    return true;
}

int vfs_close(vfs_node_t node) {
    if (node == NULL)
        return -1;
    if (node->handle == NULL)
        return 0;
    if (node == rootdir)
        return 0;
    if (node->refcount > 0)
        node->refcount--;
    if (node->refcount <= 0) {
        node->flags &= ~VFS_NODE_FLAGS_OPENED;
        bool real_close = callbackof(node, close)(node->handle);
        if (real_close) {
            if (node->flags & VFS_NODE_FLAGS_FREE_AFTER_USE) {
                vfs_free(node);
                return 0;
            }
            if (node->flags & VFS_NODE_FLAGS_DELETED) {
                vfs_free(node);
            } else {
                node->handle = NULL;
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
        if (!strcmp(all_fs[i]->name, type)) {
            ret = fs_callbacks[i]->mount(dev, node);
            if (!ret) {
                node->root = node;
                return 0;
            } else {
                printk("Mount fs %s failed, ret = %d\n", type, ret);
                return ret;
            }
        }
    }
    return -ENOENT;
}

int vfs_remount(vfs_node_t old, vfs_node_t dir) {
    int ret = callbackof(old, remount)(old, dir);
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

    ssize_t ret = callbackof(fd->node, read)(fd, addr, offset, size);
    return ret;
}

int vfs_readlink(vfs_node_t node, char *buf, size_t bufsize) {
    int ret = callbackof(node, readlink)(node, buf, 0, bufsize);
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

    ssize_t write_bytes = 0;
    write_bytes = callbackof(fd->node, write)(fd, addr, offset, size);
    if (write_bytes > 0) {
        fd->node->size = MAX(fd->node->size, offset + write_bytes);
    }
    return write_bytes;
}

int vfs_unmount(const char *path) {
    vfs_node_t node = vfs_open(path, 0);
    if (node == NULL)
        return -1;
    if (!(node->type & file_dir))
        return -1;
    if (node->fsid == 0)
        return -1;
    // list_foreach(node->child, i) {
    //     vfs_node_t child = i->data;
    //     if (child == child->root) {
    //         char *child_path = vfs_get_fullpath(child);
    //         vfs_unmount((const char *)child_path);
    //         free(child_path);
    //     }
    // }
    callbackof(node, unmount)(node);
    vfs_delete_mount_point_by_dir(node);
    return 0;
}

int vfs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    do_update(node);

    return callbackof(node, ioctl)(node->handle, cmd, arg);
}

int vfs_poll(vfs_node_t node, size_t event) {
    if (node->type & file_dir)
        return -1;
    int ret = callbackof(node, poll)(node->handle, event);
    return ret;
}

// 使用请记得free掉返回的buff
char *vfs_get_fullpath(vfs_node_t node) {
    if (node == NULL)
        return NULL;

    int inital = 32;
    vfs_node_t *nodes = (vfs_node_t *)malloc(sizeof(vfs_node_t) * inital);
    int count = 0;
    for (vfs_node_t cur = node; cur && cur != cur->parent; cur = cur->parent) {
        if (count >= inital) {
            inital *= 2;
            nodes = (vfs_node_t *)realloc(
                (void *)nodes, (size_t)(sizeof(vfs_node_t) * inital));
        }
        nodes[count++] = cur;
    }

    char *buff = (char *)malloc(512);
    memset(buff, 0, 512);
    strcpy(buff, "/");
    for (int j = count - 1; j >= 0; j--) {
        if (nodes[j] == rootdir)
            continue;

        if (!nodes[j]->name)
            continue;

        strcat(buff, nodes[j]->name);
        if (j != 0)
            strcat(buff, "/");
    }

    free(nodes);

    return buff;
}

int vfs_delete(vfs_node_t node) {
    if (node == rootdir)
        return -EOPNOTSUPP;
    int res = callbackof(node, delete)(
        node->parent ? node->parent->handle : NULL, node);
    if (res < 0) {
        return res;
    }
    node->flags |= VFS_NODE_FLAGS_DELETED;
    if (node->parent)
        llist_delete(&node->node_for_childs);
    if (node->refcount <= 0) {
        vfs_free_handle(node);
        node->handle = NULL;
        vfs_free(node);
    }

    return 0;
}

int vfs_rename(vfs_node_t node, const char *new) {
    vfs_node_t new_node = vfs_open(new, 0);
    if (new_node)
        vfs_delete(new_node);

    char *filename;
    char *last_slash = strrchr(new, '/');

    if (last_slash == NULL) {
        filename = (char *)new;
    } else {
        filename = last_slash + 1;

        if (*filename == '\0') {
            *last_slash = '\0';
            char *prev_slash = strrchr(new, '/');
            *last_slash = '/';

            if (prev_slash == NULL) {
                filename = (char *)new;
            } else {
                filename = prev_slash + 1;
            }
        }
    }

    char buf[512];
    memset(buf, 0, sizeof(buf));
    int fn_len = strlen(filename);
    int dn_len = strlen(new) - fn_len;
    memcpy(buf, new, dn_len);

    vfs_node_t new_parent = vfs_open(buf, 0);
    if (!new_parent)
        return -ENOENT;

    int ret = callbackof(node, rename)(node->handle, new);
    if (ret < 0) {
        return ret;
    }

    if (node->parent)
        llist_delete(&node->node_for_childs);
    node->parent = new_parent;
    if (node->parent)
        llist_append(&node->parent->childs, &node->node_for_childs);
    free(node->name);
    node->name = strdup(filename);

    return ret;
}

fd_t *vfs_dup(fd_t *fd) {
    fd_t *new_fd = malloc(sizeof(fd_t));
    memset(new_fd, 0, sizeof(fd_t));
    vfs_node_t node = fd->node;
    node->refcount++;
    new_fd->node = node;
    new_fd->offset = fd->offset;
    new_fd->flags = fd->flags;
    new_fd->close_on_exec = fd->close_on_exec;

    return new_fd;
}

void vfs_resize(vfs_node_t node, uint64_t size) {
    if (!(node->type & file_none))
        return;
    callbackof(node, resize)(node->handle, size);
}

void *vfs_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot,
              uint64_t flags, uint64_t offset) {
    return callbackof(fd->node, map)(fd, (void *)addr, offset, len, prot,
                                     flags);
}
