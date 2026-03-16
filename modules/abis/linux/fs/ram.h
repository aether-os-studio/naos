#pragma once

#include <fs/vfs/vfs.h>

typedef struct ramfs_node {
    char *content;
    uint64_t inode;
    uint64_t dev;
    uint64_t rdev;
    uint64_t blksz;
    uint32_t owner;
    uint32_t group;
    uint32_t type;
    uint16_t mode;
    uint32_t link_count;
    uint32_t handle_refs;
    size_t size;
    size_t capability;
} ramfs_node_t;

void ramfs_init();
