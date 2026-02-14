#pragma once

#include <fs/vfs/vfs.h>

typedef struct ramfs_node {
    vfs_node_t node;
    // for file type
    char *content;
    int size;
    int capability;
} ramfs_node_t;

void ramfs_init();
