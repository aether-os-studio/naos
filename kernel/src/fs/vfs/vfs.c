#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/fs_syscall.h"
#include "arch/arch.h"
#include "mm/mm.h"
#include "task/task.h"
#include "net/socket.h"
#include "drivers/pty.h"

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
    node->dev = 0;
    node->rdev = 0;
    node->blksz = DEFAULT_PAGE_SIZE;
    node->name = name ? strdup(name) : NULL;
    node->linkto = NULL;
    node->inode = alloc_fake_inode();
    node->type = file_none;
    node->fsid = parent ? parent->fsid : 0;
    node->root = parent ? parent->root : node;
    node->lock.l_pid = 0;
    node->lock.l_type = F_UNLCK;
    node->refcount = 0;
    node->mode = 0777;
    node->rw_hint = 0;
    if (parent)
        list_append(parent->child, node);
    return node;
}

void vfs_free(vfs_node_t vfs) {
    if (vfs == NULL)
        return;
    list_free_with(vfs->child, (free_t)vfs_free);
    vfs_close(vfs);
    callbackof(vfs, free_handle)(vfs->handle);
    free(vfs->name);
    if (vfs->linkto)
        vfs_close(vfs->linkto);
    free(vfs);
}

void vfs_free_child(vfs_node_t vfs) {
    if (vfs == NULL)
        return;
    list_free_with(vfs->child, (free_t)vfs_free);
}

static inline void do_open(vfs_node_t file) {
    if (file->handle != NULL) {
        callbackof(file, stat)(file->handle, file);
    } else {
        callbackof(file, open)(file->parent->handle, file->name, file);
    }
}

static inline void do_update(vfs_node_t file) {
    if (file->type & file_none || file->type & file_dir ||
        file->type & file_symlink || file->handle == NULL)
        do_open(file);
}

vfs_node_t vfs_child_find(vfs_node_t parent, const char *name) {
    if (!parent)
        return NULL;
    vfs_node_t child =
        list_first(parent->child, data, streq(name, ((vfs_node_t)data)->name));
    return child;
}

// 一定要记得手动设置一下child的type
vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle) {
    vfs_node_t node = vfs_child_find(parent, name);
    if (node)
        return node;
    node = vfs_node_alloc(parent, name);
    if (node == NULL)
        return NULL;
    node->handle = handle;
    return node;
}

int vfs_mkdir(const char *name) {
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task->cwd;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);
    if (*--filename == '/') {
        *filename = '\0';
    }

    while (*--filename != '/' && filename != path) {
    }
    if (filename != path) {
        *filename++ = '\0';
    } else {
        goto create;
    }

    if (strlen(path) == 0) {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
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
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_dir;
    callbackof(current, mkdir)(current->handle, filename, node);

    free(path);

    return 0;

err:
    free(path);
    return -1;
}

int vfs_mkfile(const char *name) {
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task->cwd;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);
    if (*--filename == '/') {
        *filename = '\0';
    }

    while (*--filename != '/' && filename != path) {
    }
    if (filename != path) {
        *filename++ = '\0';
    } else {
        goto create;
    }

    if (strlen(path) == 0) {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
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
            if (ret < 0) {
                free(new_current->name);
                free(new_current);
                goto err;
            }
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
        current = current_task->cwd;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);
    if (*--filename == '/') {
        *filename = '\0';
    }

    while (*--filename != '/' && filename != path) {
    }
    if (filename != path) {
        *filename++ = '\0';
    } else {
        goto create;
    }

    if (strlen(path) == 0) {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
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
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_none;
    callbackof(current, link)(current->handle, target_name, node);
    node->linkto = vfs_open(target_name);

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
        current = current_task->cwd;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);
    if (*--filename == '/') {
        *filename = '\0';
    }

    while (*--filename != '/' && filename != path) {
    }
    if (filename != path) {
        *filename++ = '\0';
    } else {
        goto create;
    }

    if (strlen(path) == 0) {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
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
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_symlink;
    ssize_t ret =
        callbackof(current, symlink)(current->handle, target_name, node);
    if (ret < 0) {
        free(path);
        return ret;
    }
    node->linkto = vfs_open_at(node->parent, target_name);

    free(path);

    return 0;

err:
    free(path);
    return -EIO;
}

int vfs_mknod(const char *name, uint16_t umode, int dev) {
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/') {
        current = current_task->cwd;
        path = strdup(name);
    } else {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);
    if (*--filename == '/') {
        *filename = '\0';
    }

    while (*--filename != '/' && filename != path) {
    }
    if (filename != path) {
        *filename++ = '\0';
    } else {
        goto create;
    }

    if (strlen(path) == 0) {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr)) {
        if (streq(buf, "."))
            continue;
        if (streq(buf, "..")) {
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
        }
        current = new_current;
        do_update(current);

        if (!(current->type & file_dir))
            goto err;
    }

create:
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
        node->type = file_stream;
        break;
    default:
        node->type = file_none;
        break;
    }
    node->dev = dev;
    node->rdev = dev;
    callbackof(current, mknod)(current->handle, filename, node, umode, dev);

    free(path);

    return 0;

err:
    free(path);
    return -1;
}

int vfs_chmod(const char *path, uint16_t mode) {
    vfs_node_t node = vfs_open(path);
    if (!node)
        return -ENOENT;
    int ret = callbackof(node, chmod)(node, mode);
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

static vfs_node_t vfs_do_search(vfs_node_t dir, const char *name) {
    return list_first(dir->child, data, streq(name, ((vfs_node_t)data)->name));
}

vfs_node_t vfs_open_at(vfs_node_t start, const char *_path) {
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
            if (current->parent == NULL)
                goto err;
            current = current->parent;
            do_update(current);
            continue;
        }
        if (!(current->type & file_dir)) {
            goto err;
        }
        current = vfs_child_find(current, buf);
        if (current == NULL)
            goto err;
        do_update(current);

        if (current->type & file_symlink) {
            if (!current->parent || !current->linkto)
                goto err;

            current->type = file_symlink | file_proxy;

            vfs_node_t target = current->linkto;
            if (!target)
                goto err;

            target->refcount++;

            current->type |= target->type;
            current->size = target->size;
            current->blksz = target->blksz;

            // current->fsid = target->fsid;
            // current->handle = target->handle;
            current->root = target->root;
            current->mode = target->mode;

            if (target->type & file_dir) {
                list_foreach(target->child, i) {
                    vfs_node_t child_node = (vfs_node_t)i->data;
                    if (!vfs_child_find(current, child_node->name)) {
                        list_append(current->child, child_node);
                        child_node->refcount++;
                    }
                }
            }

            // current = current->linkto;

            continue;
        }
    }

    free(path);
    return current;

err:
    free(path);
    return NULL;
}

vfs_node_t vfs_open(const char *_path) {
    vfs_node_t node = NULL;

    if (current_task && current_task->cwd) {
        node = vfs_open_at(current_task->cwd, _path);
    } else {
        node = vfs_open_at(rootdir, _path);
    }

    return node;
}

void vfs_update(vfs_node_t node) { do_update(node); }

bool vfs_init() {
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
    if (node->type & file_proxy) {
        node->refcount--;
        return 0;
    }
    if (node->type & file_dir)
        return 0;
    if (node->refcount > 0)
        node->refcount--;
    if (node->refcount <= 0) {
        bool real_close = callbackof(node, close)(node->handle);
        if (real_close) {
            if (node->flags & VFS_NODE_FLAGS_DELETED) {
                int res = callbackof(node, delete)(
                    node->parent ? node->parent->handle : NULL, node);
                if (res < 0) {
                    return -1;
                }
                if (node->parent)
                    list_delete(node->parent->child, node);
                callbackof(node, free_handle)(node->handle);
                node->handle = NULL;
                free(node->name);
                free(node);
            } else {
                node->handle = NULL;
            }
        }
    }

    return 0;
}

int vfs_mount(vfs_node_t dev, vfs_node_t node, const char *type) {
    if (node == NULL)
        return -1;
    if (!(node->type & file_dir))
        return -1;
    for (int i = 1; i < fs_nextid; i++) {
        if (!strcmp(all_fs[i]->name, type) &&
            fs_callbacks[i]->mount(dev, node) == 0) {
            node->fsid = i;
            node->root = node;
            return 0;
        }
    }
    return -1;
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
        return -1;

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
        return -1;

    ssize_t write_bytes = 0;
    write_bytes = callbackof(fd->node, write)(fd, addr, offset, size);
    if (write_bytes > 0) {
        fd->node->size = MAX(fd->node->size, offset + write_bytes);
    }
    return write_bytes;
}

int vfs_unmount(const char *path) {
    vfs_node_t node = vfs_open(path);
    if (node == NULL)
        return -1;
    if (!(node->type & file_dir))
        return -1;
    if (node->fsid == 0)
        return -1;
    callbackof(node, unmount)(node);
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

spinlock_t get_path_lock = {0};

// 使用请记得free掉返回的buff
char *vfs_get_fullpath(vfs_node_t node) {
    if (node == NULL)
        return NULL;
    int inital = 16;
    spin_lock(&get_path_lock);
    vfs_node_t *nodes = (vfs_node_t *)malloc(sizeof(vfs_node_t) * inital);
    int count = 0;
    for (vfs_node_t cur = node; cur; cur = cur->parent) {
        if (count >= inital) {
            inital *= 2;
            nodes = (vfs_node_t *)realloc(
                (void *)nodes, (size_t)(sizeof(vfs_node_t) * inital));
        }
        nodes[count++] = cur;
    }

    // 正常的路径都不应该超过这个数值
    char *buff = (char *)malloc(2048);
    memset(buff, 0, 2048);
    strcpy(buff, "/");
    for (int j = count - 1; j >= 0; j--) {
        if (nodes[j] == rootdir)
            continue;

        strcat(buff, nodes[j]->name);
        if (j != 0)
            strcat(buff, "/");
    }

    free(nodes);
    spin_unlock(&get_path_lock);

    return buff;
}

int vfs_delete(vfs_node_t node) {
    if (node == rootdir)
        return -1;
    node->flags |= VFS_NODE_FLAGS_DELETED;
    if (node->refcount > 0)
        return 0;
    int res = callbackof(node, delete)(
        node->parent ? node->parent->handle : NULL, node);
    if (res < 0) {
        return -1;
    }
    if (node->parent)
        list_delete(node->parent->child, node);
    callbackof(node, free_handle)(node->handle);
    node->handle = NULL;
    free(node->name);
    free(node);

    return 0;
}

int vfs_rename(vfs_node_t node, const char *new) {
    vfs_node_t new_node = vfs_open(new);
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

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    int fn_len = strlen(filename);
    int dn_len = strlen(new) - fn_len;
    memcpy(buf, new, dn_len);

    vfs_node_t new_parent = vfs_open(buf);
    if (!new_parent)
        return -ENOENT;

    int ret = callbackof(node, rename)(node->handle, new);
    if (ret < 0) {
        return ret;
    }

    if (node->parent)
        list_delete(node->parent->child, node);
    node->parent = new_parent;
    if (node->parent)
        list_append(node->parent->child, node);
    free(node->name);
    node->name = strdup(filename);

    return ret;
}

fd_t *vfs_dup(fd_t *fd) {
    fd_t *new_fd = malloc(sizeof(fd_t));
    vfs_node_t node = fd->node;
    node->refcount++;
    new_fd->node = callbackof(node, dup)(node);
    new_fd->offset = fd->offset;
    new_fd->flags = fd->flags;

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
