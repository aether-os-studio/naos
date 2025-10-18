#pragma once

#include <fs/vfs/vfs.h>

typedef struct tmpfs_node {
    vfs_node_t node;
    // for file type
    char *content;
    int size;
    int capability;
} tmpfs_node_t;

void tmpfs_init();
