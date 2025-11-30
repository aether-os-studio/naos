#pragma once

#include <libs/klibc.h>
#include <fs/termios.h>

typedef enum task_state {
    TASK_CREATING = 1,
    TASK_RUNNING,
    TASK_READY,
    TASK_BLOCKING,
    TASK_READING_STDIO,
    TASK_UNINTERRUPTABLE,
    TASK_DIED,
} task_state_t;

struct arch_context;
typedef struct arch_context arch_context_t;

struct vfs_node;
typedef struct vfs_node *vfs_node_t;

struct rlimit {
    size_t rlim_cur;
    size_t rlim_max;
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

typedef struct int_timer_internal {
    uint64_t at;
    uint64_t reset;
} int_timer_internal_t;

union sigval {
    int sival_int;
    void *sival_ptr;
};

#define SIGEV_SIGNAL 0    /* notify via signal */
#define SIGEV_NONE 1      /* other notification: meaningless */
#define SIGEV_THREAD 2    /* deliver via thread creation */
#define SIGEV_THREAD_ID 4 /* deliver to thread */

typedef struct kernel_timer {
    clockid_t clock_type;
    int sigev_signo;
    union sigval sigev_value;
    int sigev_notify;
    uint64_t expires;
    uint64_t interval;
} kernel_timer_t;

#define MAX_TIMERS_NUM 8

struct fd;
typedef struct fd fd_t;

#define MAX_FD_NUM 256

typedef struct fd_info {
    fd_t *fds[MAX_FD_NUM];
    int ref_count;
} fd_info_t;

#define TASK_NAME_MAX 128

typedef uint64_t sigset_t;
typedef void (*sighandler_t)(int);

#define SIG_DFL ((sighandler_t)0) // 默认的信号处理程序（信号句柄）
#define SIG_IGN ((sighandler_t)1) // 忽略信号的处理程序

#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SA_RESTORER 0x04000000

typedef struct sigaction {
    sighandler_t sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
} sigaction_t;

#define MINSIG 1
#define MAXSIG 65

struct task_signal_info;
typedef struct task_signal_info task_signal_info_t;

typedef struct task {
    uint64_t syscall_stack;
    uint64_t kernel_stack;
    bool is_kernel;
    uint64_t pid;
    uint64_t ppid;
    int64_t uid;
    int64_t gid;
    int64_t euid;
    int64_t egid;
    int64_t ruid;
    int64_t rgid;
    int64_t pgid;
    int64_t tgid;
    int64_t sid;
    uint64_t waitpid;
    uint64_t status;
    uint32_t cpu_id;
    char name[TASK_NAME_MAX];
    vfs_node_t exec_node;
    int priority;
    void *sched_info;
    task_state_t state;
    task_state_t current_state;
    uint64_t force_wakeup_ns;
    uint64_t load_start;
    uint64_t load_end;
    arch_context_t *arch_context;
    task_signal_info_t *signal;
    vfs_node_t cwd;
    fd_info_t *fd_info;
    vfs_node_t procfs_node;
    char *cmdline;
    int_timer_internal_t itimer_real;
    kernel_timer_t *timers[MAX_TIMERS_NUM];
    struct rlimit rlim[16];
    int *tidptr;
    bool child_vfork_done;
    bool is_vfork;
    bool is_clone;
    bool should_free;
} task_t;
