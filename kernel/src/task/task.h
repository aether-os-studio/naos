#pragma once

#include <fs/vfs/pipe.h>
#include <task/signal.h>
#include <fs/termios.h>

extern uint64_t jiffies;

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

#define EHDR_START_ADDR 0x0000300000000000
#define INTERPRETER_EHDR_ADDR 0x0000200000000000
#define INTERPRETER_BASE_ADDR 0x0000100000000000

#define USER_MMAP_START 0x0000400000000000
#define USER_MMAP_END 0x0000600000000000

#define USER_BRK_START 0x0000700000000000
#define USER_BRK_END 0x0000800000000000

#define MAX_TASK_NUM 1024

#define TASK_NAME_MAX 128

#define MAX_FD_NUM 64

#define current_task arch_get_current()

#define CLONE_VM 0x00000100             /* set if VM shared between processes */
#define CLONE_FS 0x00000200             /* set if fs info shared between processes */
#define CLONE_FILES 0x00000400          /* set if open files shared between processes */
#define CLONE_SIGHAND 0x00000800        /* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD 0x00001000          /* set if a pidfd should be placed in parent */
#define CLONE_PTRACE 0x00002000         /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK 0x00004000          /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT 0x00008000         /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000         /* Same thread group? */
#define CLONE_NEWNS 0x00020000          /* New mount namespace group */
#define CLONE_SYSVSEM 0x00040000        /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS 0x00080000         /* create a new TLS for the child */
#define CLONE_PARENT_SETTID 0x00100000  /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* clear the TID in the child */
#define CLONE_DETACHED 0x00400000       /* Unused, ignored */
#define CLONE_UNTRACED 0x00800000       /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID 0x01000000   /* set the TID in the child */
#define CLONE_NEWCGROUP 0x02000000      /* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000         /* New utsname namespace */
#define CLONE_NEWIPC 0x08000000         /* New ipc namespace */
#define CLONE_NEWUSER 0x10000000        /* New user namespace */
#define CLONE_NEWPID 0x20000000         /* New pid namespace */
#define CLONE_NEWNET 0x40000000         /* New network namespace */
#define CLONE_IO 0x80000000             /* Clone io context */

typedef enum task_state
{
    TASK_RUNNING = 1,
    TASK_READY,
    TASK_BLOCKING,
    TASK_DIED,
} task_state_t;

struct arch_context;
typedef struct arch_context arch_context_t;

struct vfs_node;
typedef struct vfs_node *vfs_node_t;

struct itimerval
{
    struct timeval it_interval;
    struct timeval it_value;
};

typedef struct int_timer_internal
{
    uint64_t at;
    uint64_t reset;
} int_timer_internal_t;

union sigval;

#define SIGEV_SIGNAL 0    /* notify via signal */
#define SIGEV_NONE 1      /* other notification: meaningless */
#define SIGEV_THREAD 2    /* deliver via thread creation */
#define SIGEV_THREAD_ID 4 /* deliver to thread */

typedef struct kernel_timer
{
    clockid_t clock_type;
    int sigev_signo;
    union sigval sigev_value;
    int sigev_notify;
    uint64_t expires;
    uint64_t interval;
} kernel_timer_t;

#define MAX_TIMERS_NUM 8

struct rlimit;
struct fd;
typedef struct fd fd_t;

typedef struct task
{
    uint64_t pid;
    uint64_t ppid;
    int64_t uid;
    int64_t gid;
    int64_t euid;
    int64_t egid;
    int64_t ruid;
    int64_t rgid;
    int64_t pgid;
    uint64_t waitpid;
    uint64_t status;
    uint32_t cpu_id;
    char name[TASK_NAME_MAX];
    uint64_t jiffies;
    task_state_t state;
    task_state_t current_state;
    uint64_t kernel_stack;
    uint64_t syscall_stack;
    uint64_t mmap_start;
    uint64_t brk_start;
    uint64_t brk_end;
    uint64_t load_start;
    uint64_t load_end;
    arch_context_t *arch_context;
    sigaction_t actions[MAXSIG];
    uint64_t signal;
    uint64_t blocked;
    vfs_node_t cwd;
    fd_t *fds[MAX_FD_NUM];
    uint64_t timer_slack_ns;
    termios term;
    uint32_t tmp_rec_v;
    char *cmdline;
    int_timer_internal_t itimer_real;
    kernel_timer_t *timers[MAX_TIMERS_NUM];
    struct rlimit rlim[16];
} task_t;

void sched_update_itimer();

task_t *task_create(const char *name, void (*entry)(uint64_t), uint64_t arg);
void task_init();

struct pt_regs;

uint64_t task_fork(struct pt_regs *regs, bool vfork);
uint64_t task_execve(const char *path, const char **argv, const char **envp);
uint64_t task_exit(int64_t code);

#define WNOHANG 1
#define WUNTRACED 2

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options);
uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp, int *parent_tid, int *child_tid, uint64_t tls);
struct timespec;
uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem);

size_t sys_setitimer(int which, struct itimerval *value, struct itimerval *old);

task_t *task_search(task_state_t state, uint32_t cpu_id);
int task_block(task_t *task, task_state_t state, int timeout_ms);
void task_unblock(task_t *task, int reason);

#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_SET_SECCOMP 22
#define PR_GET_SECCOMP 21
#define PR_SET_TIMERSLACK 23
#define SECCOMP_MODE_STRICT 1

uint64_t sys_prctl(uint64_t options, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);

int sys_timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
int sys_timer_settime(timer_t timerid, const struct itimerval *new_value, struct itimerval *old_value);

extern task_t *tasks[MAX_TASK_NUM];
extern task_t *idle_tasks[MAX_CPU_NUM];
