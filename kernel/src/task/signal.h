#pragma once

#include <libs/klibc.h>

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT SIGABRT
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL 29
#define SIGPWR 30
#define SIGSYS 31
#define SIGUNUSED SIGSYS

#define MINSIG 1
#define MAXSIG 65

#define SIGMASK(sig) (1UL << (sig))

typedef enum signal_internal
{
    SIGNAL_INTERNAL_CORE = 0,
    SIGNAL_INTERNAL_TERM,
    SIGNAL_INTERNAL_IGN,
    SIGNAL_INTERNAL_STOP,
    SIGNAL_INTERNAL_CONT
} signal_internal_t;

// 不阻止在指定的信号处理程序中再收到该信号
#define SIG_NOMASK 0x40000000

// 信号句柄一旦被调用过就恢复到默认处理句柄
#define SIG_ONESHOT 0x80000000

struct task;
typedef struct task task_t;

bool signals_pending_quick(task_t *task);

#define SIG_BLOCK 0   /* for blocking signals */
#define SIG_UNBLOCK 1 /* for unblocking signals */
#define SIG_SETMASK 2 /* for setting the signal mask */

typedef uint64_t sigset_t;
typedef void (*sighandler_t)(int);

#define SIG_DFL ((sighandler_t)0) // 默认的信号处理程序（信号句柄）
#define SIG_IGN ((sighandler_t)1) // 忽略信号的处理程序

typedef struct sigaction
{
    sighandler_t sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
} sigaction_t;

int sys_sgetmask();
int sys_ssetmask(int how, sigset_t *nset, sigset_t *oset);
int sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction);
struct pt_regs;
void sys_sigreturn(struct pt_regs *regs);
int sys_sigsuspend(const sigset_t *mask);
int sys_kill(int pid, int sig);

union sigval
{
    int sival_int;
    void *sival_ptr;
};

struct sigevent
{
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    union
    {
        char __pad[64 - 2 * sizeof(int) - sizeof(union sigval)];
        int sigev_notify_thread_id;
        struct
        {
            void (*sigev_notify_function)(union sigval);
            void *sigev_notify_attributes;
        } __sev_thread;
    } __sev_fields;
};

struct signalfd_siginfo
{
    uint32_t ssi_signo;   // 信号编号
    int32_t ssi_errno;    // 错误代码（通常为0）
    int32_t ssi_code;     // 信号来源（如SI_USER）
    uint32_t ssi_pid;     // 发送进程PID
    uint32_t ssi_uid;     // 发送用户UID
    int32_t ssi_fd;       // 相关文件描述符（若适用）
    uint32_t ssi_tid;     // 内核定时器ID（若适用）
    uint32_t ssi_band;    // 带宽事件（用于SIGPOLL）
    uint32_t ssi_overrun; // 定时器超限计数
    uint32_t ssi_trapno;  // 陷阱号（SIGSEGV等）
    int32_t ssi_status;   // 退出状态（SIGCHLD）
    int32_t ssi_int;      // 信号携带的整数值
    uint64_t ssi_ptr;     // 信号携带的指针值
    uint64_t ssi_utime;   // 用户时间（SIGCHLD）
    uint64_t ssi_stime;   // 系统时间（SIGCHLD）
    uint64_t ssi_addr;    // 触发地址（SIGSEGV/SIGBUS）
    uint8_t __pad[48];    // 填充至128字节
};

struct signalfd_ctx
{
    sigset_t sigmask;               // 监控的信号集合
    struct signalfd_siginfo *queue; // 信号事件队列
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
};
