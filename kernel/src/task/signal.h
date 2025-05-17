#pragma once

#include <libs/klibc.h>

#define SIGHUP 1UL
#define SIGINT 2UL
#define SIGQUIT 3UL
#define SIGILL 4UL
#define SIGTRAP 5UL
#define SIGABRT 6UL
#define SIGIOT SIGABRT
#define SIGBUS 7UL
#define SIGFPE 8UL
#define SIGKILL 9UL
#define SIGUSR1 10UL
#define SIGSEGV 11UL
#define SIGUSR2 12UL
#define SIGPIPE 13UL
#define SIGALRM 14UL
#define SIGTERM 15UL
#define SIGSTKFLT 16UL
#define SIGCHLD 17UL
#define SIGCONT 18UL
#define SIGSTOP 19UL
#define SIGTSTP 20UL
#define SIGTTIN 21UL
#define SIGTTOU 22UL
#define SIGURG 23UL
#define SIGXCPU 24UL
#define SIGXFSZ 25UL
#define SIGVTALRM 26UL
#define SIGPROF 27UL
#define SIGWINCH 28UL
#define SIGIO 29UL
#define SIGPOLL 29UL
#define SIGPWR 30UL
#define SIGSYS 31UL
#define SIGUNUSED SIGSYS

#define MINSIG 1UL
#define MAXSIG 32UL

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
typedef void (*sighandler_t)(void);

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
void sys_sigreturn();
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

struct signalfd_ctx
{
    sigset_t sigmask;       // 监控的信号集合
    struct sigevent *queue; // 信号事件队列
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
};
