#include <fs/vfs/sys.h>
#include <drivers/kernel_logger.h>

static vfs_node_t sysfs_root = NULL;
static int sysfs_id = 0;

static vfs_node_t bus_root = NULL;
static vfs_node_t class_root = NULL;
static vfs_node_t graphics_root = NULL;
static vfs_node_t subsystem_root = NULL;

static void dummy() {}

void sysfs_open(void *parent, const char *name, vfs_node_t node)
{
    sysfs_handle_t *parent_handle = parent;
}

int sysfs_stat(void *file, vfs_node_t node)
{
    return 0;
}

ssize_t sysfs_read(void *file, void *addr, size_t offset, size_t size)
{
    sysfs_handle_t *handle = file;
    size_t content_len = strlen(handle->content);

    if (offset >= content_len)
    {
        return 0;
    }

    size_t remaining = content_len - offset;
    size_t read_size = (size < remaining) ? size : remaining;

    memcpy(addr, handle->content + offset, read_size);
    return read_size;
}

static struct vfs_callback callback = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = sysfs_open,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)sysfs_read,
    .write = (vfs_write_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = sysfs_stat,
    .ioctl = (vfs_ioctl_t)dummy,
};

void sysfs_init()
{
    sysfs_id = vfs_regist("sysfs", &callback);
    sysfs_root = vfs_node_alloc(rootdir, "sys");
    sysfs_root->type = file_dir;
    sysfs_root->fsid = sysfs_id;
    bus_root = vfs_child_append(sysfs_root, "bus", NULL);
    bus_root->type = file_dir;
    class_root = vfs_child_append(sysfs_root, "class", NULL);
    class_root->type = file_dir;
    graphics_root = vfs_child_append(class_root, "graphics", NULL);
    graphics_root->type = file_dir;
    subsystem_root = vfs_child_append(graphics_root, "subsystem", NULL);
    subsystem_root->type = file_none;
    sysfs_handle_t *subsystem_handle = malloc(sizeof(sysfs_handle_t));
    memset(subsystem_handle, 0, sizeof(sysfs_handle_t));
    sprintf(subsystem_handle->content, "/dev/fb0"); // 默认设备
    subsystem_root->handle = subsystem_handle;
}
