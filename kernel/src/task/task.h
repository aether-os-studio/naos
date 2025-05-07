#pragma once

#include <fs/vfs/vfs.h>
#include <fs/vfs/pipe.h>
#include <task/signal.h>

#define AT_NULL 0
#define AT_IGNORE 1
#define AT_EXECFD 2
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_NOTELF 10
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_CLKTCK 17
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_FPUCW 18
#define AT_DCACHEBSIZE 19
#define AT_ICACHEBSIZE 20
#define AT_UCACHEBSIZE 21
#define AT_IGNOREPPC 22
#define AT_SECURE 23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_EXECFN 31
#define AT_SYSINFO 32
#define AT_SYSINFO_EHDR 33

#define EHDR_START_ADDR 0x0000600000000000

#define USER_BRK_START 0x0000700000000000
#define USER_BRK_END 0x00007fffffffffff

#define USER_MMAP_START 0x0000400000000000

#define MAX_TASK_NUM 1024

#define TASK_NAME_MAX 128

#define MAX_FD_NUM 32

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

struct Container;
typedef struct Container Container;

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
    uint64_t mmap_start;
    uint64_t brk_start;
    uint64_t brk_end;
    arch_context_t *arch_context;
    sigaction_t actions[MAXSIG];
    uint64_t signal;
    uint64_t blocked;
    vfs_node_t cwd;
    vfs_node_t fds[MAX_FD_NUM];
} task_t;

task_t *task_create(const char *name, void (*entry)());
void task_init();

struct pt_regs;

uint64_t task_fork(struct pt_regs *regs);
uint64_t task_execve(const char *path, char *const *argv, char *const *envp);
uint64_t task_exit(int64_t code);
uint64_t sys_waitpid(uint64_t pid, int *status);

task_t *task_search(task_state_t state, uint32_t cpu_id);
int task_block(task_t *task, task_state_t state, int timeout_ms);
void task_unblock(task_t *task, int reason);

extern task_t *tasks[MAX_TASK_NUM];
extern task_t *idle_tasks[MAX_CPU_NUM];
