#pragma once

#include <libs/klibc.h>
#include <libs/mutex.h>
#include <libs/llist.h>
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

struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

typedef struct int_timer_internal {
    uint64_t at;
    uint64_t reset;
} int_timer_internal_t;

typedef union sigval {
    int sival_int;
    void *sival_ptr;
} sigval_t;

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
    mutex_t fdt_lock;
    int ref_count;
} fd_info_t;

#define with_fd_info_lock(fd_info, op)                                         \
    do {                                                                       \
        if (!fd_info)                                                          \
            break;                                                             \
        mutex_lock(&fd_info->fdt_lock);                                        \
        do {                                                                   \
            op;                                                                \
        } while (0);                                                           \
        mutex_unlock(&fd_info->fdt_lock);                                      \
    } while (0)

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

union __sifields {
    /* kill() */
    struct {
        int _pid;      /* sender's pid */
        uint32_t _uid; /* sender's uid */
    } _kill;

    /* POSIX.1b timers */
    struct {
        int _tid;         /* timer id */
        int _overrun;     /* overrun count */
        sigval_t _sigval; /* same as below */
        int _sys_private; /* Not used by the kernel. Historic leftover. Always
                             0. */
    } _timer;

    /* POSIX.1b signals */
    struct {
        int _pid;      /* sender's pid */
        uint32_t _uid; /* sender's uid */
        sigval_t _sigval;
    } _rt;

    /* SIGCHLD */
    struct {
        int _pid;      /* which child */
        uint32_t _uid; /* sender's uid */
        int _status;   /* exit code */
        long _utime;
        long _stime;
    } _sigchld;

    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
    struct {
        void *_addr; /* faulting insn/memory ref. */

#define __ADDR_BND_PKEY_PAD                                                    \
    (__alignof__(void *) < sizeof(short) ? sizeof(short) : __alignof__(void *))
        union {
            /* used on alpha and sparc */
            int _trapno; /* TRAP # which caused the signal */
            /*
             * used when si_code=BUS_MCEERR_AR or
             * used when si_code=BUS_MCEERR_AO
             */
            short _addr_lsb; /* LSB of the reported address */
            /* used when si_code=SEGV_BNDERR */
            struct {
                char _dummy_bnd[__ADDR_BND_PKEY_PAD];
                void *_lower;
                void *_upper;
            } _addr_bnd;
            /* used when si_code=SEGV_PKUERR */
            struct {
                char _dummy_pkey[__ADDR_BND_PKEY_PAD];
                uint32_t _pkey;
            } _addr_pkey;
            /* used when si_code=TRAP_PERF */
            struct {
                unsigned long _data;
                uint32_t _type;
                uint32_t _flags;
            } _perf;
        };
    } _sigfault;

    /* SIGPOLL */
    struct {
        long _band; /* POLL_IN, POLL_OUT, POLL_MSG */
        int _fd;
    } _sigpoll;

    /* SIGSYS */
    struct {
        void *_call_addr;   /* calling user insn */
        int _syscall;       /* triggering system call number */
        unsigned int _arch; /* AUDIT_ARCH_* of syscall */
    } _sigsys;
};

#define __SIGINFO                                                              \
    struct {                                                                   \
        int si_signo;                                                          \
        int si_errno;                                                          \
        int si_code;                                                           \
        union __sifields _sifields;                                            \
    }

typedef __SIGINFO siginfo_t;

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
    uint64_t last_sched_in_ns;
    uint64_t user_time_ns;
    uint64_t system_time_ns;
    uint64_t child_user_time_ns;
    uint64_t child_system_time_ns;
    uint32_t cpu_id;
    char name[TASK_NAME_MAX];
    vfs_node_t exec_node;
    int priority;
    void *sched_info;
    task_state_t state;
    task_state_t current_state;
    const char *blocking_reason;
    uint64_t force_wakeup_ns;
    uint64_t load_start;
    uint64_t load_end;
    arch_context_t *arch_context;
    task_signal_info_t *signal;
    vfs_node_t cwd;
    fd_info_t *fd_info;
    struct llist_header timerfd_list;
    shm_mapping_t *shm_ids;
    vfs_node_t procfs_node;
    char *cmdline;
    int_timer_internal_t itimer_real;
    kernel_timer_t *timers[MAX_TIMERS_NUM];
    struct rlimit rlim[16];
    uint64_t parent_death_sig;
    int *tidptr;
    uint64_t clone_flags;
    bool is_kernel;
    bool is_clone;
    bool child_vfork_done;
    bool should_free;
} task_t;
