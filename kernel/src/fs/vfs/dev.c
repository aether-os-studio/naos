#include "fs/vfs/dev.h"
#include <fs/fs_syscall.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>

#define FLANTERM_IN_FLANTERM
#include <libs/flanterm/flanterm_private.h>
#include <libs/flanterm/backends/fb_private.h>

static int devfs_id = 0;
static vfs_node_t devfs_root = NULL;

devfs_handle_t devfs_handles[MAX_DEV_NUM];

static int dummy()
{
    return -1;
}

ssize_t devfs_read(void *file, void *addr, size_t offset, size_t size)
{
    devfs_handle_t handle = (devfs_handle_t)file;
    if (handle->read)
    {
        return handle->read(handle->data, offset, addr, size);
    }

    return 0;
}

ssize_t devfs_write(void *file, const void *addr, size_t offset, size_t size)
{
    devfs_handle_t handle = (devfs_handle_t)file;
    if (handle->write)
    {
        return handle->write(handle->data, offset, addr, size);
    }

    return 0;
}

void devfs_open(void *parent, const char *name, vfs_node_t node)
{
    (void)parent;

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] != NULL && !strncmp(devfs_handles[i]->name, name, MAX_DEV_NAME_LEN))
        {
            devfs_handle_t handle = devfs_handles[i];
            node->handle = handle;
            break;
        }
    }
}

void devfs_close(void *current)
{
    (void)current;
}

int devfs_ioctl(devfs_handle_t handle, ssize_t cmd, ssize_t arg)
{
    if (handle->ioctl)
    {
        return handle->ioctl(handle->data, cmd, arg);
    }

    return 0;
}

int devfs_mkdir(void *parent, const char *name, vfs_node_t node)
{
    vfs_node_t child = vfs_child_append(node, name, NULL);
    child->type = file_dir;

    return 0;
}

int devfs_mkfile(void *parent, const char *name, vfs_node_t node)
{
    return 0;
}

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = devfs_open,
    .close = devfs_close,
    .read = devfs_read,
    .write = devfs_write,
    .mkdir = (vfs_mk_t)devfs_mkdir,
    .mkfile = (vfs_mk_t)devfs_mkfile,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)devfs_ioctl,
};

#define MAX_FB_NUM 2

void regist_dev(const char *name,
                ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len),
                ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len),
                ssize_t (*ioctl)(void *data, ssize_t cmd, ssize_t arg),
                void *data)
{
    const char *new_name = name;

    vfs_node_t dev = devfs_root;

    if (strstr(name, "/") != NULL)
    {
        new_name = strstr(name, "/") + 1;
        const char *path_len = new_name - name;
        char new_path[256];
        strcpy(new_path, "/dev/");
        strncpy(new_path + 5, name, path_len);
        vfs_mkdir((const char *)new_path);
        dev = vfs_open((const char *)new_path);
    }

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] == NULL)
        {
            devfs_handles[i] = malloc(sizeof(struct devfs_handle));
            strncpy(devfs_handles[i]->name, new_name, MAX_DEV_NAME_LEN);
            devfs_handles[i]->read = read;
            devfs_handles[i]->write = write;
            devfs_handles[i]->ioctl = ioctl;
            devfs_handles[i]->data = data;
            vfs_node_t child = vfs_child_append(dev, devfs_handles[i]->name, NULL);
            child->type = file_block;
            if (!strncmp(devfs_handles[i]->name, "std", 3))
                child->type = file_stream;
            break;
        }
    }
}

ssize_t stdin_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)len;

    ssize_t read_len = 0;

    char scancode = (char)get_keyboard_input();
    if (scancode != 0)
    {
        *((uint8_t *)buf + read_len) = scancode;
        read_len++;
    }

    return read_len;
}

ssize_t stdout_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    (void)data;
    (void)offset;

    for (uint64_t i = 0; i < len; i++)
    {
        printk("%c", ((const char *)buf)[i]);
    }

    return (ssize_t)len;
}

extern struct flanterm_context *ft_ctx;

ssize_t stdio_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    switch (cmd)
    {
    case TIOCGWINSZ:
        *(struct winsize *)arg = (struct winsize){
            .ws_xpixel = ((struct flanterm_fb_context *)ft_ctx)->width,
            .ws_ypixel = ((struct flanterm_fb_context *)ft_ctx)->height,
            .ws_col = ft_ctx->cols,
            .ws_row = ft_ctx->rows,
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
    }

    return -ENOTTY;
}

void stdio_init()
{
    regist_dev("stdin", stdin_read, NULL, stdio_ioctl, NULL);
    regist_dev("stdout", NULL, stdout_write, stdio_ioctl, NULL);
    regist_dev("stderr", NULL, stdout_write, stdio_ioctl, NULL);

    regist_dev("tty", stdin_read, stdout_write, stdio_ioctl, NULL);
}

uint64_t next = 0;

ssize_t random_dev_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
#if defined(__x86_64__)
    tm time;
    time_read_bcd(&time);
    next = mktime(&time);
#endif
    next = next * 1103515245 + 12345;
    return ((unsigned)(next / 65536) % 32768);
}

ssize_t null_dev_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

ssize_t null_dev_write(void *data, uint64_t offset, void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

void dev_init()
{
    devfs_id = vfs_regist("devfs", &callbacks);

    devfs_root = vfs_node_alloc(rootdir, "dev");
    devfs_root->type = file_dir;
    devfs_root->fsid = devfs_id;

    memset(devfs_handles, 0, sizeof(devfs_handles));

    regist_dev("null", null_dev_read, null_dev_write, NULL, NULL);
    regist_dev("random", random_dev_read, NULL, NULL, NULL);
}
