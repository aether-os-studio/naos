#include "fs/vfs/dev.h"
#include <fs/syscall.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>

#define FLANTERM_IN_FLANTERM
#include <libs/flanterm/flanterm_private.h>
#include <libs/flanterm/backends/fb_private.h>

static int devfs_id = 0;
static vfs_node_t devfs_root = NULL;

devfs_handle_t devfs_handles[MAX_DEV_NUM];

static void dummy() {}

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

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = devfs_open,
    .close = devfs_close,
    .read = devfs_read,
    .write = devfs_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
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
    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] == NULL)
        {
            devfs_handles[i] = malloc(sizeof(struct devfs_handle));
            strncpy(devfs_handles[i]->name, name, MAX_DEV_NAME_LEN);
            devfs_handles[i]->read = read;
            devfs_handles[i]->write = write;
            devfs_handles[i]->ioctl = ioctl;
            devfs_handles[i]->data = data;
            vfs_child_append(devfs_root, devfs_handles[i]->name, NULL);
            break;
        }
    }
}

ssize_t stdin_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)len;

    uint8_t scancode = get_keyboard_input();
    *(uint8_t *)buf = scancode;

    return 1;
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

ssize_t stdout_ioctl(void *data, ssize_t cmd, ssize_t arg)
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
    default:
        return (uint64_t)-ENOSYS;
    }
}

void stdio_init()
{
    regist_dev("stdin", stdin_read, NULL, NULL, NULL);
    regist_dev("stdout", NULL, stdout_write, stdout_ioctl, NULL);
    regist_dev("stderr", NULL, stdout_write, NULL, NULL);
}

void dev_init()
{
    devfs_id = vfs_regist("devfs", &callbacks);

    devfs_root = vfs_node_alloc(rootdir, "dev");
    devfs_root->type = file_dir;
    devfs_root->fsid = devfs_id;

    memset(devfs_handles, 0, sizeof(devfs_handles));
}
