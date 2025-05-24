#pragma once

#include <libs/klibc.h>

#define PIPE_BUFF 1024

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
    uint32_t read_ptr;
    uint32_t write_ptr;
    char buf[PIPE_BUFF];
    int assigned;

    int writeFds;
    int readFds;

    spinlock_t lock;

    task_block_list_t blocking_read;
    task_block_list_t blocking_write;
} pipe_info_t;

typedef struct pipe_specific pipe_specific_t;
struct pipe_specific
{
    bool write;
    pipe_info_t *info;
};
