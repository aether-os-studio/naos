#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

#define PIPE_BUFF 65536
#define PIPE_ATOMIC_MAX MIN(PIPE_BUFF, PAGE_SIZE)

#define MAX_PIPES 32

struct task;
typedef struct task task_t;

struct spinlock;
typedef struct spinlock spinlock_t;

struct vfs_inode;
typedef struct vfs_inode vfs_node_t;

typedef struct pipe_info {
    uint32_t ptr;
    char *buf;

    int write_fds;
    int read_fds;

    vfs_node_t *read_node;
    vfs_node_t *write_node;

    spinlock_t lock;
} pipe_info_t;

typedef struct pipe_specific pipe_specific_t;
struct pipe_specific {
    bool read;
    bool write;
    pipe_info_t *info;
};

ssize_t pipefs_named_read(struct vfs_file *file, void *buf, size_t count,
                          loff_t *ppos);
ssize_t pipefs_named_write(struct vfs_file *file, const void *buf, size_t count,
                           loff_t *ppos);
__poll_t pipefs_named_poll(struct vfs_file *file, struct vfs_poll_table *pt);
int pipefs_named_open(struct vfs_inode *inode, struct vfs_file *file);
int pipefs_named_release(struct vfs_inode *inode, struct vfs_file *file);
void pipefs_named_evict_inode(struct vfs_inode *inode);
