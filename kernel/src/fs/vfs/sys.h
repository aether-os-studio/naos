#pragma once

#include <fs/vfs/vfs.h>

typedef struct sysfs_handle
{
    vfs_node_t node;
    void *private_data;
    char name[128];
    char content[256];
} sysfs_handle_t;

