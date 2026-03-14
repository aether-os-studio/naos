#pragma once

#include <fs/vfs/vfs.h>

typedef struct cgroupfs_node {
    vfs_node_t node;
    // for file type
    char *content;
    int size;
    int capability;
} cgroupfs_node_t;
