#pragma once

#include "../partition.h"
#include "vfs.h"

#define MAX_DEV_NUM 64
#define MAX_DEV_NAME_LEN 32

typedef struct devfs_handle
{
    char name[MAX_DEV_NAME_LEN];
    ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len);
    ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len);
    void *data;
} *devfs_handle_t;

typedef struct partition_node
{
    vfs_node_t node;
} *partition_node_t;

extern partition_node_t dev_nodes[MAX_PARTITIONS_NUM];

void regist_dev(const char *name,
                ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len),
                ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len),
                void *data);

void dev_init();
