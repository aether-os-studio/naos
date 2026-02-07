#pragma once

#include <libs/klibc.h>

#define PIPE_BUFF (512 * 1024)

#define MAX_PIPES 32

struct task;
typedef struct task task_t;

struct spinlock;
typedef struct spinlock spinlock_t;

typedef struct pipe_info {
    uint32_t ptr;
    char *buf;

    int write_fds;
    int read_fds;

    spinlock_t lock;
} pipe_info_t;

struct vfs_node;
typedef struct vfs_node *vfs_node_t;

typedef struct pipe_specific pipe_specific_t;
struct pipe_specific {
    bool write;
    pipe_info_t *info;
    vfs_node_t node;
};
