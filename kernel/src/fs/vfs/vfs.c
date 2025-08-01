#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/fs_syscall.h"
#include "arch/arch.h"
#include "mm/mm.h"
#include "task/task.h"
#include "net/socket.h"
#include "drivers/pty.h"

vfs_node_t rootdir = NULL;
char *id_to_callback_name[256];

static int empty_func()
{
    return -ENOSYS;
}

static struct vfs_callback vfs_empty_callback;

vfs_callback_t fs_callbacks[256] = {
    [0] = &vfs_empty_callback,
};
static int fs_nextid = 1;

#define callbackof(node, _name_) (fs_callbacks[(node)->fsid]->_name_)

vfs_node_t vfs_node_alloc(vfs_node_t parent, const char *name)
{
    vfs_node_t node = malloc(sizeof(struct vfs_node));
    if (node == NULL)
        return NULL;
    memset(node, 0, sizeof(struct vfs_node));
    node->parent = parent;
    node->spin.lock = 0;
    node->dev = 0;
    node->rdev = 0;
    node->blksz = DEFAULT_PAGE_SIZE;
    node->name = name ? strdup(name) : NULL;
    node->linkto = NULL;
    node->type = file_none;
    node->fsid = parent ? parent->fsid : 0;
    node->root = parent ? parent->root : node;
    node->lock.l_pid = 0;
    node->lock.l_type = F_UNLCK;
    node->refcount = 0;
    node->mode = 0777;
    node->rw_hint = 0;
    if (parent)
        list_prepend(parent->child, node);
    return node;
}

void vfs_free(vfs_node_t vfs)
{
    if (vfs == NULL)
        return;
    list_free_with(vfs->child, (free_t)vfs_free);
    vfs_close(vfs);
    free(vfs->name);
    if (vfs->linkto)
        vfs_close(vfs->linkto);
    free(vfs);
}

void vfs_free_child(vfs_node_t vfs)
{
    if (vfs == NULL)
        return;
    list_free_with(vfs->child, (free_t)vfs_free);
}

static inline void do_open(vfs_node_t file)
{
    spin_lock(&file->spin);
    if (file->handle != NULL)
    {
        callbackof(file, stat)(file->handle, file);
    }
    else
    {
        callbackof(file, open)(file->parent->handle, file->name, file);
    }
    spin_unlock(&file->spin);
}

static inline void do_update(vfs_node_t file)
{
    if (file->type & file_none || file->type & file_dir || file->type & file_symlink || file->handle == NULL)
        do_open(file);
}

vfs_node_t vfs_child_find(vfs_node_t parent, const char *name)
{
    return list_first(parent->child, data, streq(name, ((vfs_node_t)data)->name));
}

// 一定要记得手动设置一下child的type
vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle)
{
    vfs_node_t node = vfs_child_find(parent, name);
    if (node)
        return node;
    node = vfs_node_alloc(parent, name);
    if (node == NULL)
        return NULL;
    node->handle = handle;
    return node;
}

int vfs_mkdir(const char *name)
{
    if (name[0] != '/')
        return -1;
    char *path = strdup(name + 1);
    char *save_ptr = path;
    vfs_node_t current = rootdir;
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr))
    {
        const vfs_node_t father = current;
        if (streq(buf, "."))
            continue;
        if (streq(buf, ".."))
        {
            if (current->parent && current->type & file_dir)
            {
                current = current->parent;
                goto upd;
            }
            else
            {
                goto err;
            }
        }
        current = vfs_child_find(current, buf);

    upd:
        if (current == NULL)
        {
            current = vfs_node_alloc(father, buf);
            current->type = file_dir;
            callbackof(father, mkdir)(father->handle, buf, current);
            do_update(current);
        }
        else
        {
            do_update(current);
            if (current->type != file_dir)
                goto err;
        }
    }

    free(path);
    return 0;

err:
    free(path);
    return -1;
}

int vfs_mkfile(const char *name)
{
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/')
    {
        current = current_task->cwd;
        path = strdup(name);
    }
    else
    {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);

    while (*--filename != '/' && filename != path)
    {
    }
    if (filename != path)
    {
        *filename++ = '\0';
    }
    else
    {
        goto create;
    }

    if (strlen(path) == 0)
    {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr))
    {
        if (streq(buf, "."))
            continue;
        if (streq(buf, ".."))
        {
            if (!current->parent || current->type != file_dir)
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL)
        {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
        }
        current = new_current;
        do_update(current);

        if (current->type != file_dir)
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
int vfs_link(const char *name, const char *target_name)
{
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/')
    {
        current = current_task->cwd;
        path = strdup(name);
    }
    else
    {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);

    while (*--filename != '/' && filename != path)
    {
    }
    if (filename != path)
    {
        *filename++ = '\0';
    }
    else
    {
        goto create;
    }

    if (strlen(path) == 0)
    {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr))
    {
        if (streq(buf, "."))
            continue;
        if (streq(buf, ".."))
        {
            if (!current->parent || current->type != file_dir)
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL)
        {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
        }
        current = new_current;
        do_update(current);

        if (current->type != file_dir)
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_none;
    callbackof(current, link)(current->handle, target_name, node);
    node->linkto = vfs_open(target_name);

    free(path);

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
int vfs_symlink(const char *name, const char *target_name)
{
    vfs_node_t current = rootdir;
    char *path;
    if (name[0] != '/')
    {
        current = current_task->cwd;
        path = strdup(name);
    }
    else
    {
        path = strdup(name + 1);
    }

    char *save_ptr = path;
    char *filename = path + strlen(path);

    while (*--filename != '/' && filename != path)
    {
    }
    if (filename != path)
    {
        *filename++ = '\0';
    }
    else
    {
        goto create;
    }

    if (strlen(path) == 0)
    {
        free(path);
        return -1;
    }
    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr))
    {
        if (streq(buf, "."))
            continue;
        if (streq(buf, ".."))
        {
            if (!current->parent || current->type != file_dir)
                goto err;
            current = current->parent;
            continue;
        }
        vfs_node_t new_current = vfs_child_find(current, buf);
        if (new_current == NULL)
        {
            new_current = vfs_node_alloc(current, buf);
            new_current->type = file_dir;
            callbackof(current, mkdir)(current->handle, buf, new_current);
        }
        current = new_current;
        do_update(current);

        if (current->type != file_dir)
            goto err;
    }

create:
    vfs_node_t node = vfs_child_append(current, filename, NULL);
    node->type = file_symlink;
    callbackof(current, symlink)(current->handle, target_name, node);
    node->linkto = vfs_open(target_name);

    free(path);

    return 0;

err:
    free(path);
    return -1;
}

int vfs_regist(const char *name, vfs_callback_t callback)
{
    (void)name;

    if (callback == NULL)
        return -1;
    for (size_t i = 0; i < sizeof(struct vfs_callback) / sizeof(void *); i++)
    {
        if (((void **)callback)[i] == NULL)
            return -1;
    }
    int id = fs_nextid++;
    fs_callbacks[id] = callback;
    id_to_callback_name[id] = strdup(name);
    return id;
}

static vfs_node_t vfs_do_search(vfs_node_t dir, const char *name)
{
    return list_first(dir->child, data, streq(name, ((vfs_node_t)data)->name));
}

vfs_node_t vfs_open_at(vfs_node_t start, const char *_path)
{
    if (!start)
        return NULL;

    if (_path == NULL)
        return NULL;
    vfs_node_t current = start;
    char *path;
    if (_path[0] == '/')
    {
        if (_path[1] == '\0')
        {
            return rootdir;
        }
        current = rootdir;
        path = strdup(_path + 1);
    }
    else
    {
        path = strdup(_path);
    }

    char *save_ptr = path;

    for (const char *buf = pathtok(&save_ptr); buf; buf = pathtok(&save_ptr))
    {
        if (streq(buf, "."))
            continue;
        if (streq(buf, ".."))
        {
            if (current->parent == NULL)
                goto err;
            current = current->parent;
            do_update(current);
            continue;
        }
        if (!(current->type & file_dir))
        {
            goto err;
        }
        current = vfs_child_find(current, buf);
        if (current == NULL)
            goto err;
        do_update(current);

        if (current->type & file_symlink)
        {
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

            current->fsid = target->fsid;
            current->handle = target->handle;
            current->root = target->root;
            current->mode = target->mode;

            if (target->type & file_dir)
            {
                list_foreach(target->child, i)
                {
                    vfs_node_t child_node = (vfs_node_t)i->data;
                    if (!vfs_child_find(current, child_node->name))
                    {
                        list_prepend(current->child, child_node);
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

vfs_node_t vfs_open(const char *_path)
{
    vfs_node_t node = NULL;

    if (current_task && current_task->cwd)
    {
        node = vfs_open_at(current_task->cwd, _path);
    }
    else
    {
        node = vfs_open_at(rootdir, _path);
    }

    return node;
}

void vfs_update(vfs_node_t node)
{
    do_update(node);
}

bool vfs_init()
{
    memset(id_to_callback_name, 0, sizeof(id_to_callback_name));
    for (size_t i = 0; i < sizeof(struct vfs_callback) / sizeof(void *); i++)
    {
        ((void **)&vfs_empty_callback)[i] = &empty_func;
    }

    rootdir = vfs_node_alloc(NULL, NULL);
    rootdir->type = file_dir;
    rootdir->fsid = 0;
    return true;
}

int vfs_close(vfs_node_t node)
{
    if (node == NULL)
        return -1;
    if (node->handle == NULL)
        return 0;
    if (node == rootdir)
        return 0;
    if (node->type & file_proxy)
    {
        node->refcount--;
        return 0;
    }
    if (node->type & file_dir)
        return 0;
    spin_lock(&node->spin);
    if (node->refcount > 0)
        node->refcount--;
    if (node->refcount == 0)
    {
        bool real_close = callbackof(node, close)(node->handle);
        if (real_close)
        {
            if (node->linkto)
                vfs_close(node->linkto);
            node->handle = NULL;
        }
    }
    spin_unlock(&node->spin);

    return 0;
}

int vfs_mount(const char *src, vfs_node_t node, const char *type)
{
    if (node == NULL)
        return -1;
    if (!(node->type & file_dir))
        return -1;
    for (int i = 1; i < fs_nextid; i++)
    {
        if (!strcmp(id_to_callback_name[i], type) && fs_callbacks[i]->mount(src, node) == 0)
        {
            node->fsid = i;
            node->root = node;
            return 0;
        }
    }
    return -1;
}

ssize_t vfs_read(vfs_node_t file, void *addr, size_t offset, size_t size)
{
    do_update(file);
    if (file->type & file_dir)
        return -1;
    spin_lock(&file->spin);
    fd_t fd;
    fd.node = file;
    fd.flags = 0;
    fd.offset = offset;
    ssize_t ret = callbackof(file, read)(&fd, addr, offset, size);
    spin_unlock(&file->spin);
    return ret;
}

ssize_t vfs_read_fd(fd_t *fd, void *addr, size_t offset, size_t size)
{
    do_update(fd->node);
    if (fd->node->type & file_dir)
        return -1;
    spin_lock(&fd->node->spin);
    ssize_t ret = callbackof(fd->node, read)(fd, addr, offset, size);
    spin_unlock(&fd->node->spin);
    return ret;
}

int vfs_readlink(vfs_node_t node, char *buf, size_t bufsize)
{
    return callbackof(node, readlink)(node, buf, 0, bufsize);
}

ssize_t vfs_write(vfs_node_t file, const void *addr, size_t offset, size_t size)
{
    do_update(file);
    if (file->type & file_dir)
        return -1;
    spin_lock(&file->spin);
    fd_t fd;
    fd.node = file;
    fd.flags = 0;
    fd.offset = offset;
    ssize_t write_bytes = 0;
    write_bytes = callbackof(file, write)(&fd, addr, offset, size);
    if (write_bytes > 0)
    {
        file->size = max(file->size, offset + write_bytes);
    }
    spin_unlock(&file->spin);
    return write_bytes;
}

ssize_t vfs_write_fd(fd_t *fd, const void *addr, size_t offset, size_t size)
{
    do_update(fd->node);
    if (fd->node->type & file_dir)
        return -1;
    spin_lock(&fd->node->spin);
    ssize_t write_bytes = 0;
    write_bytes = callbackof(fd->node, write)(fd, addr, offset, size);
    if (write_bytes > 0)
    {
        fd->node->size = max(fd->node->size, offset + write_bytes);
    }
    spin_unlock(&fd->node->spin);
    return write_bytes;
}

int vfs_unmount(const char *path)
{
    vfs_node_t node = vfs_open(path);
    if (node == NULL)
        return -1;
    if (node->type != file_dir)
        return -1;
    if (node->fsid == 0)
        return -1;
    if (node->parent)
    {
        vfs_node_t cur = node;
        node = node->parent;
        if (cur->root == cur)
        {
            vfs_free_child(cur);
            callbackof(cur, unmount)(cur->handle);
            cur->fsid = node->fsid; // 交给上级
            cur->root = node->root;
            cur->handle = NULL;
            cur->child = NULL;
            // cur->type   = file_none;
            if (cur->fsid)
                do_update(cur);
            return 0;
        }
    }
    return -1;
}

int tty_mode = KD_TEXT;
int tty_kbmode = K_XLATE;
struct vt_mode current_vt_mode = {0};

extern int pts_fsid;

int vfs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg)
{
    do_update(node);

    if (node->fsid != pts_fsid)
    {
        switch (cmd)
        {
        case TIOCGWINSZ:
            size_t addr;
            size_t width;
            size_t height;
            size_t bpp;
            size_t cols;
            size_t rows;

            os_terminal_get_screen_info(&addr, &width, &height, &bpp, &cols, &rows);

            *(struct winsize *)arg = (struct winsize){
                .ws_xpixel = width,
                .ws_ypixel = height,
                .ws_col = cols,
                .ws_row = rows,
            };
            return 0;
        case TIOCSCTTY:
            return 0;
        case TIOCGPGRP:
            int *pid = (int *)arg;
            *pid = current_task->pid;
            return 0;
        case TIOCSPGRP:
            return 0;
        case TCGETS:
            if (check_user_overflow(arg, sizeof(termios)))
            {
                return -EFAULT;
            }
            memcpy((void *)arg, &current_task->term, sizeof(termios));
            return 0;
        case TCSETS:
            if (check_user_overflow(arg, sizeof(termios)))
            {
                return -EFAULT;
            }
            memcpy(&current_task->term, (void *)arg, sizeof(termios));
            return 0;
        case TCSETSW:
            if (check_user_overflow(arg, sizeof(termios)))
            {
                return -EFAULT;
            }
            memcpy(&current_task->term, (void *)arg, sizeof(termios));
            return 0;
        case TIOCSWINSZ:
            return 0;
        case KDGETMODE:
            *(int *)arg = tty_mode;
            return 0;
        case KDSETMODE:
            tty_mode = *(int *)arg;
            return 0;
        case KDGKBMODE:
            *(int *)arg = tty_kbmode;
            return 0;
        case KDSKBMODE:
            tty_kbmode = *(int *)arg;
            return 0;
        case VT_SETMODE:
            memcpy(&current_vt_mode, (void *)arg, sizeof(struct vt_mode));
            return 0;
        case VT_GETMODE:
            memcpy((void *)arg, &current_vt_mode, sizeof(struct vt_mode));
            return 0;
        case VT_ACTIVATE:
            return 0;
        case VT_WAITACTIVE:
            return 0;
        case VT_GETSTATE:
            struct vt_state *state = (struct vt_state *)arg;
            state->v_active = 1; // 当前活动终端
            state->v_state = 0;  // 状态标志
            return 0;
        case VT_OPENQRY:
            *(int *)arg = 1;
            return 0;
        default:
            return callbackof(node, ioctl)(node->handle, cmd, arg);
        }
    }
    else
    {
        return callbackof(node, ioctl)(node->handle, cmd, arg);
    }
}

int vfs_poll(vfs_node_t node, size_t event)
{
    if (node->type & file_dir)
        return -1;
    return callbackof(node, poll)(node->handle, event);
}

spinlock_t get_path_lock = {0};

// 使用请记得free掉返回的buff
char *vfs_get_fullpath(vfs_node_t node)
{
    if (node == NULL)
        return NULL;
    int inital = 16;
    spin_lock(&get_path_lock);
    vfs_node_t *nodes = (vfs_node_t *)malloc(sizeof(vfs_node_t) * inital);
    int count = 0;
    for (vfs_node_t cur = node; cur; cur = cur->parent)
    {
        if (count >= inital)
        {
            inital *= 2;
            nodes = (vfs_node_t *)realloc((void *)nodes, (size_t)(sizeof(vfs_node_t) * inital));
        }
        nodes[count++] = cur;
    }
    // 正常的路径都不应该超过这个数值
    char *buff = (char *)malloc(1024);
    strcpy(buff, "/");
    for (int j = count - 1; j >= 0; j--)
    {
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

int vfs_delete(vfs_node_t node)
{
    if (node == rootdir)
        return -1;
    int res = callbackof(node, delete)(node->parent->handle, node);
    if (res < 0)
        return -1;
    list_delete(node->parent->child, node);
    node->handle = NULL;
    vfs_free(node);
    return 0;
}

int vfs_rename(vfs_node_t node, const char *new)
{
    return callbackof(node, rename)(node->handle, new);
}

fd_t *vfs_dup(fd_t *fd)
{
    fd_t *new_fd = malloc(sizeof(fd_t));
    vfs_node_t node = fd->node;
    node->refcount++;
    new_fd->node = callbackof(node, dup)(node);
    new_fd->offset = 0;
    new_fd->flags = fd->flags;

    return new_fd;
}

void vfs_resize(vfs_node_t node, uint64_t size)
{
    if (node->type != file_none)
        return;
    callbackof(node, resize)(node->handle, size);
}

void *vfs_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset)
{
    return callbackof(fd->node, map)(fd, (void *)addr, offset, len, prot, flags);
}
