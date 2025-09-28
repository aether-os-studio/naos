#pragma once

#include <fs/vfs/vfs.h>

typedef struct tmpfs_node *tmpfs_node_t;

struct tmpfs_node {
    tmpfs_node_t parent;
    char *name;
    uint64_t size;
    char *content;
    uint32_t type;
    uint64_t dev;
    uint64_t rdev;
    uint16_t mode;
    spinlock_t lock;
};

void tmpfs_init();
