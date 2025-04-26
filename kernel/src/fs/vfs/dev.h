#pragma once

#include "../partition.h"
#include "vfs.h"

typedef struct partition_node
{
    vfs_node_t node;
} *partition_node_t;

extern partition_node_t dev_nodes[MAX_PARTITIONS_NUM];

void dev_init();
