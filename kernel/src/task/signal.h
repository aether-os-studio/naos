#pragma once

#include <libs/klibc.h>
#include <task/task_struct.h>

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

#define SIGMASK(sig) (1UL << (sig))

typedef enum signal_internal {
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

int signals_pending_quick(task_t *task);

#define SIG_BLOCK 0   /* for blocking signals */
#define SIG_UNBLOCK 1 /* for unblocking signals */
#define SIG_SETMASK 2 /* for setting the signal mask */

struct timespec;

uint64_t sys_sgetmask();
uint64_t sys_ssetmask(int how, sigset_t *nset, sigset_t *oset);
uint64_t sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction);
struct pt_regs;
void sys_sigreturn(struct pt_regs *regs);
uint64_t sys_sigsuspend(const sigset_t *mask);
uint64_t sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                             const struct timespec *uts, size_t sigsetsize);
uint64_t sys_rt_sigqueueinfo(uint64_t tgid, uint64_t sig, siginfo_t *info);
uint64_t sys_kill(int pid, int sig);

struct sigevent {
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    union {
        char __pad[64 - 2 * sizeof(int) - sizeof(union sigval)];
        int sigev_notify_thread_id;
        struct {
            void (*sigev_notify_function)(union sigval);
            void *sigev_notify_attributes;
        } __sev_thread;
    } __sev_fields;
};

#define SI_USER 0      /* sent by kill, sigsend, raise */
#define SI_KERNEL 0x80 /* sent by the kernel from somewhere */
#define SI_QUEUE -1    /* sent by sigqueue */
#define SI_TIMER -2    /* sent by timer expiration */
#define SI_MESGQ -3    /* sent by real time mesq state change */
#define SI_ASYNCIO -4  /* sent by AIO completion */
#define SI_SIGIO -5    /* sent by queued SIGIO */
#define SI_TKILL -6    /* sent by tkill system call */
#define SI_DETHREAD -7 /* sent by execve() killing subsidiary threads */
#define SI_ASYNCNL -60 /* sent by glibc async name lookup completion */

struct signalfd_siginfo {
    uint32_t ssi_signo;   // 信号号
    int32_t ssi_errno;    // errno 值
    int32_t ssi_code;     // 信号代码 (CLD_EXITED, CLD_KILLED 等)
    uint32_t ssi_pid;     // 发送进程 PID
    uint32_t ssi_uid;     // 发送进程 UID
    int32_t ssi_fd;       // 文件描述符 (SIGIO)
    uint32_t ssi_tid;     // 内核定时器 ID
    uint32_t ssi_band;    // Band event (SIGIO)
    uint32_t ssi_overrun; // POSIX 定时器溢出计数
    uint32_t ssi_trapno;  // Trap 号
    int32_t ssi_status;   // 退出状态或信号
    int32_t ssi_int;      // sigqueue() 发送的整数
    uint64_t ssi_ptr;     // sigqueue() 发送的指针
    uint64_t ssi_utime;   // 用户 CPU 时间
    uint64_t ssi_stime;   // 系统 CPU 时间
    uint64_t ssi_addr;    // 产生信号的地址 (SIGSEGV 等)
    uint8_t __pad[48];    // 填充至128字节
};

struct signalfd_ctx {
    sigset_t sigmask;               // 监控的信号集合
    struct signalfd_siginfo *queue; // 信号事件队列
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
    vfs_node_t node;
};

void signal_init();

void task_commit_signal(task_t *task, int sig, siginfo_t *info);
