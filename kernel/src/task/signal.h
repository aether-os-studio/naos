#pragma once

#include <libs/klibc.h>

enum SIGNAL
{
    SIGHUP = 1,   // 挂断控制终端或进程
    SIGINT,       // 来自键盘的中断
    SIGQUIT,      // 来自键盘的退出
    SIGILL,       // 非法指令
    SIGTRAP,      // 跟踪断点
    SIGABRT,      // 异常结束
    SIGIOT = 6,   // 异常结束
    SIGUNUSED,    // 没有使用
    SIGFPE,       // 协处理器出错
    SIGKILL = 9,  // 强迫进程终止
    SIGUSR1,      // 用户信号 1，进程可使用
    SIGSEGV,      // 无效内存引用
    SIGUSR2,      // 用户信号 2，进程可使用
    SIGPIPE,      // 管道写出错，无读者
    SIGALRM,      // 实时定时器报警
    SIGTERM = 15, // 进程终止
    SIGSTKFLT,    // 栈出错（协处理器）
    SIGCHLD,      // 子进程停止或被终止
    SIGCONT,      // 恢复进程继续执行
    SIGSTOP,      // 停止进程的执行
    SIGTSTP,      // tty 发出停止进程，可忽略
    SIGTTIN,      // 后台进程请求输入
    SIGTTOU = 22, // 后台进程请求输出
};

#define MINSIG 1
#define MAXSIG 63

#define SIGMASK(sig) (1UL << ((sig) - 1))

// 不阻止在指定的信号处理程序中再收到该信号
#define SIG_NOMASK 0x40000000

// 信号句柄一旦被调用过就恢复到默认处理句柄
#define SIG_ONESHOT 0x80000000

#define SIG_DFL ((void (*)(int))0) // 默认的信号处理程序（信号句柄）
#define SIG_IGN ((void (*)(int))1) // 忽略信号的处理程序

#define SIG_BLOCK 0   /* for blocking signals */
#define SIG_UNBLOCK 1 /* for unblocking signals */
#define SIG_SETMASK 2 /* for setting the signal mask */

typedef uint64_t sigset_t;

typedef struct sigaction
{
    void (*sa_handler)(int);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
} sigaction_t;

int sys_sgetmask();
int sys_ssetmask(int how, sigset_t *nset, sigset_t *oset);
int sys_signal(int sig, uint64_t handler, uint64_t restorer);
int sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction);
void sys_sigreturn();
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
