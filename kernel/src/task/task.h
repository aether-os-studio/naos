#pragma once

#include <fs/vfs/vfs.h>

#define USER_BRK_START 0x0000700000000000
#define USER_BRK_END 0x00007fffffffffff

#define MAX_TASK_NUM 1024

#define TASK_NAME_MAX 128

#define MAX_FD_NUM 16

#define current_task arch_get_current()

typedef enum task_state
{
    TASK_RUNNING = 1,
    TASK_READY,
    TASK_BLOCKING,
    TASK_DIED,
} task_state_t;

struct arch_context;
typedef struct arch_context arch_context_t;

typedef struct task
{
    uint64_t pid;
    uint64_t ppid;
    uint64_t waitpid;
    uint64_t status;
    uint32_t cpu_id;
    char name[TASK_NAME_MAX];
    uint64_t jiffies;
    task_state_t state;
    uint64_t kernel_stack;
    uint64_t syscall_stack;
    uint64_t brk_start;
    uint64_t brk_end;
    arch_context_t *arch_context;
    uint64_t signal;
    vfs_node_t cwd;
    vfs_node_t fds[MAX_FD_NUM];
} task_t;

task_t *task_create(const char *name, void (*entry)());
void task_init();

uint64_t task_fork();
uint64_t task_execve(const char *path, char *const *argv, char *const *envp);
uint64_t task_exit(int64_t code);

task_t *task_search(task_state_t state, uint32_t cpu_id);

extern task_t *tasks[MAX_TASK_NUM];
extern task_t *idle_tasks[MAX_CPU_NUM];
