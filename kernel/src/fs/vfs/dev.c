#include "fs/vfs/dev.h"
#include <drivers/kernel_logger.h>

static int devfs_id = 0;
static vfs_node_t devfs_root = NULL;

static void dummy() {}

int devfs_mount(const char *src, vfs_node_t node)
{
    if (src != NULL)
        return -1;
    node->fsid = devfs_id;
    devfs_root = node;
    return 0;
}

ssize_t partition_dev_read(void *file, void *addr, size_t offset, size_t size)
{
    vfs_node_t node = (vfs_node_t)file;
    return partition_read(node->devid, offset, addr, size);
}

ssize_t partition_dev_write(void *file, const void *addr, size_t offset, size_t size)
{
    vfs_node_t node = (vfs_node_t)file;
    return partition_write(node->devid, offset, (void *)addr, size);
}

ssize_t devfs_read(void *file, void *addr, size_t offset, size_t size)
{
    partition_node_t node = (partition_node_t)file;
    if (node->node->type == file_block)
    {
        return partition_dev_read((void *)node->node, addr, offset, size);
    }

    return 0;
}

ssize_t devfs_write(void *file, const void *addr, size_t offset, size_t size)
{
    partition_node_t node = (partition_node_t)file;
    if (node->node->type == file_block)
    {
        return partition_dev_write((void *)node->node, addr, offset, size);
    }

    return 0;
}

static struct vfs_callback callbacks = {
    .mount = devfs_mount,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = devfs_read,
    .write = devfs_write,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .stat = (vfs_stat_t)dummy,
};

#define MAX_FB_NUM 2

partition_node_t dev_nodes[MAX_PARTITIONS_NUM];

void dev_init()
{
    devfs_id = vfs_regist("devfs", &callbacks);

    devfs_root = vfs_node_alloc(rootdir, "dev");
    devfs_root->type = file_dir;

    uint64_t i;
    for (i = 0; i < partition_num; i++)
    {
        char buf[6];
        sprintf(buf, "part%d", i);
        dev_nodes[i] = (partition_node_t)malloc(sizeof(struct partition_node));
        memset(dev_nodes[0], 0, sizeof(struct partition_node));
        dev_nodes[i]->node = vfs_node_alloc(devfs_root, (const char *)buf);
        dev_nodes[i]->node->devid = i;
        dev_nodes[i]->node->type = file_block;
        dev_nodes[i]->node->fsid = devfs_id;
        dev_nodes[i]->node->handle = (void *)dev_nodes[i];
    }
}
