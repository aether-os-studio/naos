#pragma once

#include <libs/klibc.h>
#include <fs/termios.h>
#include <mm/shm.h>

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

#define MAX_FD_NUM 512
#define MAX_SHM_NUM 32

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

#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3
#define CLD_TRAPPED 4
#define CLD_STOPPED 5
#define CLD_CONTINUED 6

typedef struct {
    int si_signo; /* 信号编号 */
    int si_errno; /* errno值 */
    int si_code;  /* 信号代码 */

    union {
        int _pad[29]; /* 为兼容性保留的空间 */

        /* SIGKILL, SIGTERM, SIGINT, ... */
        struct {
            int64_t si_pid; /* 发送进程的PID */
            int64_t si_uid; /* 发送进程的真实UID */
        } __kill;

        /* POSIX.1b 计时器 */
        struct {
            int si_tid;      /* 定时器ID */
            int si_overrun;  /* 超过次数 */
            void *si_sigval; /* 信号值 */
        } __timer;

        /* POSIX.1b 实时信号 */
        struct {
            int64_t si_pid;  /* 发送进程的PID */
            int64_t si_uid;  /* 发送进程的真实UID */
            void *si_sigval; /* 信号值 */
        } __rt;

        /* SIGCHLD */
        struct {
            int64_t si_pid; /* 终止的子进程PID */
            int64_t si_uid; /* 子进程的真实UID */
            int si_status;  /* 退出状态 */
            int64_t si_utime;
            int64_t si_stime;
        } __sigchld;

        /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP */
        struct {
            void *si_addr; /* 导致错误的地址 */
            short si_addr_lsb;
            union {
                struct {
                    void *si_lower;
                    void *si_upper;
                } __addr_bnd;
                unsigned int si_pkey;
            } __bounds;
        } __sigfault;

        /* SIGPOLL/SIGIO */
        struct {
            long si_band; /* POLL_IN, POLL_OUT, POLL_MSG */
            int si_fd;
        } __sigpoll;

        /* SIGSYS */
        struct {
            void *si_call_addr;   /* 系统调用指令地址 */
            int si_syscall;       /* 系统调用编号 */
            unsigned int si_arch; /* 体系结构 */
        } __sigsys;
    } __si_fields;
} siginfo_t;

typedef struct pending_signal {
    int sig;
    siginfo_t info;
    bool processed;
} pending_signal_t;

struct pt_regs;

typedef struct task_signal_info {
    spinlock_t signal_lock;
    sigset_t signal;
    pending_signal_t pending_signal;
    sigset_t blocked;
    sigaction_t actions[MAXSIG];
} task_signal_info_t;

typedef struct task {
    uint64_t syscall_stack;
    uint64_t kernel_stack;
    uint64_t signal_syscall_stack;
    uint64_t preempt;
    uint64_t pid;
    uint64_t ppid;
    int64_t uid;
    int64_t gid;
    int64_t euid;
    int64_t egid;
    int64_t suid;
    int64_t sgid;
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
    const char *blocking_reason;
    uint64_t sleep_clock_id;
    uint64_t sleep_start_ns;
    uint64_t force_wakeup_ns;
    uint64_t load_start;
    uint64_t load_end;
    arch_context_t *arch_context;
    task_signal_info_t *signal;
    vfs_node_t cwd;
    fd_info_t *fd_info;
    shm_mapping_t *shm_ids;
    vfs_node_t procfs_node;
    char *cmdline;
    int_timer_internal_t itimer_real;
    kernel_timer_t *timers[MAX_TIMERS_NUM];
    struct rlimit rlim[16];
    int *tidptr;
    bool is_kernel;
    bool is_vfork;
    bool is_clone;
    bool is_in_syscall;
    bool ignore_signal;
    bool child_vfork_done;
    bool should_free;
} task_t;
