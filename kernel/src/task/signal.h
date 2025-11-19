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

typedef struct {
    int32_t si_signo; // Signal number
    int32_t si_errno; // Error number (if applicable)
    int32_t si_code;  // Signal code

    union {
        int32_t _pad[128 - 3 * sizeof(int32_t) / sizeof(int32_t)];

        // Kill
        struct {
            int32_t si_pid;  // Sending process ID
            uint32_t si_uid; // Real user ID of sending process
        } _kill;

        // Timer
        struct {
            int32_t si_tid;     // Timer ID
            int32_t si_overrun; // Overrun count
            int32_t si_sigval;  // Signal value
        } _timer;

        // POSIX.1b signals
        struct {
            int32_t si_pid;    // Sending process ID
            uint32_t si_uid;   // Real user ID of sending process
            int32_t si_sigval; // Signal value
        } _rt;

        // SIGCHLD
        struct {
            int32_t si_pid;    // Sending process ID
            uint32_t si_uid;   // Real user ID of sending process
            int32_t si_status; // Exit value or signal
            int32_t si_utime;  // User time consumed
            int32_t si_stime;  // System time consumed
        } _sigchld;

        // SIGILL, SIGFPE, SIGSEGV, SIGBUS
        struct {
            uintptr_t si_addr;   // Faulting instruction or data address
            int32_t si_addr_lsb; // LSB of the address (if applicable)
        } _sigfault;

        // SIGPOLL
        struct {
            int32_t si_band; // Band event
            int32_t si_fd;   // File descriptor
        } _sigpoll;

        // SIGSYS
        struct {
            uintptr_t si_call_addr; // Calling user insn
            int32_t si_syscall;     // Number of syscall
            uint32_t si_arch;       // Architecture
        } _sigsys;
    } _sifields;
} siginfo_t;

struct timespec;

uint64_t sys_sgetmask();
uint64_t sys_ssetmask(int how, sigset_t *nset, sigset_t *oset);
uint64_t sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction);
struct pt_regs;
void sys_sigreturn(struct pt_regs *regs);
uint64_t sys_sigsuspend(const sigset_t *mask);
uint64_t sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                             const struct timespec *uts, size_t sigsetsize);
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

struct signalfd_siginfo {
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

struct signalfd_ctx {
    sigset_t sigmask;               // 监控的信号集合
    struct signalfd_siginfo *queue; // 信号事件队列
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
    vfs_node_t node;
};
