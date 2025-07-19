#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

#define PIPE_BUFF 16384

#define MAX_PIPES 32

struct task;
typedef struct task task_t;

typedef struct task_block_list
{
    struct task_block_list *next;
    task_t *task;
} task_block_list_t;

typedef struct pipe_info
{
    char buf[PIPE_BUFF];
    int assigned;

    int write_fds;
    int read_fds;

    spinlock_t lock;

    task_block_list_t blocking_read;
    task_block_list_t blocking_write;
} pipe_info_t;

typedef struct pipe_specific pipe_specific_t;
struct pipe_specific
{
    fd_t *fd;
    bool write;
    pipe_info_t *info;
    vfs_node_t node;
};
