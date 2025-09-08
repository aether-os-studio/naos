#include <task/signal.h>
#include <fs/vfs/vfs.h>
#include <arch/arch.h>
#include <task/task.h>

#define SI_MAX_SIZE 128

typedef struct
{
    int32_t si_signo; // Signal number
    int32_t si_errno; // Error number (if applicable)
    int32_t si_code;  // Signal code

    union
    {
        int32_t _pad[128 - 3 * sizeof(int32_t) / sizeof(int32_t)];

        // Kill
        struct
        {
            int32_t si_pid;  // Sending process ID
            uint32_t si_uid; // Real user ID of sending process
        } _kill;

        // Timer
        struct
        {
            int32_t si_tid;     // Timer ID
            int32_t si_overrun; // Overrun count
            int32_t si_sigval;  // Signal value
        } _timer;

        // POSIX.1b signals
        struct
        {
            int32_t si_pid;    // Sending process ID
            uint32_t si_uid;   // Real user ID of sending process
            int32_t si_sigval; // Signal value
        } _rt;

        // SIGCHLD
        struct
        {
            int32_t si_pid;    // Sending process ID
            uint32_t si_uid;   // Real user ID of sending process
            int32_t si_status; // Exit value or signal
            int32_t si_utime;  // User time consumed
            int32_t si_stime;  // System time consumed
        } _sigchld;

        // SIGILL, SIGFPE, SIGSEGV, SIGBUS
        struct
        {
            uintptr_t si_addr;   // Faulting instruction or data address
            int32_t si_addr_lsb; // LSB of the address (if applicable)
        } _sigfault;

        // SIGPOLL
        struct
        {
            int32_t si_band; // Band event
            int32_t si_fd;   // File descriptor
        } _sigpoll;

        // SIGSYS
        struct
        {
            uintptr_t si_call_addr; // Calling user insn
            int32_t si_syscall;     // Number of syscall
            uint32_t si_arch;       // Architecture
        } _sigsys;
    } _sifields;
} siginfo_t;

struct sigcontext
{
    arch_signal_frame_t arch;
    uint64_t reserved1[8];
};

signal_internal_t signal_internal_decisions[MAXSIG] = {0};

void signal_init()
{
    signal_internal_decisions[SIGABRT] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGALRM] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGBUS] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGCHLD] = SIGNAL_INTERNAL_IGN;
    // signal_internal_decisions[SIGCLD] = SIGNAL_INTERNAL_IGN;
    signal_internal_decisions[SIGCONT] = SIGNAL_INTERNAL_CONT;
    // signal_internal_decisions[SIGEMT] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGFPE] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGHUP] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGILL] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGINT] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGIO] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGIOT] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGKILL] = SIGNAL_INTERNAL_TERM;
    // signal_internal_decisions[SIGLOST] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGPIPE] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGPOLL] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGPROF] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGPWR] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGQUIT] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGSEGV] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGSTKFLT] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGSTOP] = SIGNAL_INTERNAL_STOP;
    signal_internal_decisions[SIGTSTP] = SIGNAL_INTERNAL_STOP;
    signal_internal_decisions[SIGSYS] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGTERM] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGTRAP] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGTTIN] = SIGNAL_INTERNAL_STOP;
    signal_internal_decisions[SIGTTOU] = SIGNAL_INTERNAL_STOP;
    signal_internal_decisions[SIGUNUSED] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGURG] = SIGNAL_INTERNAL_IGN;
    signal_internal_decisions[SIGUSR1] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGUSR2] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGVTALRM] = SIGNAL_INTERNAL_TERM;
    signal_internal_decisions[SIGXCPU] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGXFSZ] = SIGNAL_INTERNAL_CORE;
    signal_internal_decisions[SIGWINCH] = SIGNAL_INTERNAL_IGN;
}

bool signals_pending_quick(task_t *task)
{
    sigset_t pending_list = task->signal;
    sigset_t unblocked_list = pending_list & (~task->blocked);
    for (int i = MINSIG; i <= MAXSIG; i++)
    {
        if (!(unblocked_list & SIGMASK(i)))
            continue;
        sigaction_t *action = &task->actions[i];
        sighandler_t user_handler = action->sa_handler;
        if (user_handler == SIG_IGN)
            continue;
        if (user_handler == SIG_DFL && signal_internal_decisions[i] == SIGNAL_INTERNAL_IGN)
            continue;

        return true;
    }
    return false;
}

// 获取信号屏蔽位图
int sys_sgetmask()
{
    return current_task->blocked;
}

// 设置信号屏蔽位图
int sys_ssetmask(int how, sigset_t *nset, sigset_t *oset)
{
    if (oset)
        *oset = current_task->blocked;
    if (nset)
    {
        uint64_t safe = *nset;
        safe &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP)); // nuh uh!
        switch (how)
        {
        case SIG_BLOCK:
            current_task->blocked |= safe;
            break;
        case SIG_UNBLOCK:
            current_task->blocked &= ~(safe);
            break;
        case SIG_SETMASK:
            current_task->blocked = safe;
            break;
        default:
            return -EINVAL;
            break;
        }
    }

    return 0;
}

int sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction)
{
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL)
    {
        return -EINVAL;
    }

    sigaction_t *ptr = &current_task->actions[sig];
    if (oldaction)
    {
        *oldaction = *ptr;
    }

    if (action)
    {
        *ptr = *action;
    }

    if (ptr->sa_flags & SIG_NOMASK)
    {
        ptr->sa_mask = 0;
    }
    else
    {
        ptr->sa_mask |= SIGMASK(sig);
    }

    return 0;
}

spinlock_t sigreturn_lock = {0};

void sys_sigreturn(struct pt_regs *regs)
{
    spin_lock(&sigreturn_lock);

#if defined(__x86_64__)
    arch_disable_interrupt();

    struct pt_regs *context = (struct pt_regs *)current_task->kernel_stack - 1;

    memcpy(context, &current_task->signal_saved_regs, sizeof(struct pt_regs));

    current_task->arch_context->ctx = context;

    current_task->call_in_signal = 0;

    spin_unlock(&sigreturn_lock);

    asm volatile(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(current_task->arch_context->ctx));
#elif defined(__aarch64__)
#elif defined(__loongarch64)
#else
    // todo: other architectures
#endif
}

int sys_sigsuspend(const sigset_t *mask)
{
    sigset_t old = current_task->blocked;

    current_task->blocked = *mask;

    while (!signals_pending_quick(current_task))
    {
        arch_yield();
    }

    current_task->blocked = old;

    return -EINTR;
}

int sys_kill(int pid, int sig)
{
    if (sig < MINSIG || sig > MAXSIG)
    {
        return 0;
    }

    if (pid < 0)
    {
        for (uint64_t i = cpu_count; i < MAX_TASK_NUM; i++)
        {
            if (tasks[i] && tasks[i]->ppid == current_task->pid)
            {
                sys_kill(tasks[i]->pid, sig);
            }
        }

        return 0;
    }

    task_t *task = tasks[pid];

    if (!task)
    {
        return 0;
    }

    // if (task->ppid != 0 && task->ppid != task->pid)
    // {
    //     task_t *parent = tasks[task->ppid];
    //     if (!parent)
    //     {
    //         return 0;
    //     }

    //     void *handler = parent->actions[SIGCHLD].sa_handler;
    //     if (!(handler == SIG_DFL || handler == SIG_IGN))
    //     {
    //         parent->signal |= SIGMASK(SIGCHLD);
    //     }

    //     if (parent->state == TASK_BLOCKING)
    //     {
    //         task_unblock(parent, SIGCHLD);
    //     }
    // }

    task->signal |= SIGMASK(sig);

    task_unblock(task, -sig);

    return 0;
}

extern int signalfdfs_id;

spinlock_t signal_lock = {0};

void task_signal()
{
    arch_disable_interrupt();

    spin_lock(&signal_lock);

    if (current_task->call_in_signal)
    {
        spin_unlock(&signal_lock);
        return;
    }

    uint64_t map = current_task->signal & (~current_task->blocked);
    if (!map)
    {
        spin_unlock(&signal_lock);
        return;
    }

    int sig = 1;
    for (; sig <= MAXSIG; sig++)
    {
        if (map & SIGMASK(sig))
        {
            current_task->signal &= (~SIGMASK(sig));
            break;
        }
    }

    if (sig == SIGKILL)
    {
        spin_unlock(&signal_lock);
        task_exit(-sig);
        return;
    }

    for (int i = 0; i < MAX_FD_NUM; i++)
    {
        if (current_task->fd_info->fds[i])
        {
            vfs_node_t node = current_task->fd_info->fds[i]->node;
            if (node && node->fsid == signalfdfs_id)
            {
                struct signalfd_ctx *ctx = node->handle;

                struct signalfd_siginfo info;
                memset(&info, 0, sizeof(struct sigevent));
                info.ssi_signo = sig;

                memcpy(&ctx->queue[ctx->queue_head], &info, sizeof(struct signalfd_siginfo));
                ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_size;
                if (ctx->queue_head == ctx->queue_tail)
                {
                    ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
                }
            }
        }
    }

    sigaction_t *ptr = &current_task->actions[sig];

    if (ptr->sa_handler == SIG_IGN)
    {
        spin_unlock(&signal_lock);
        return;
    }

    if (ptr->sa_handler == SIG_DFL)
    {
        spin_unlock(&signal_lock);
        return;
    }

#if defined(__x86_64__)
    struct pt_regs *f = (struct pt_regs *)current_task->syscall_stack - 1;

    memcpy(&current_task->signal_saved_regs, current_task->arch_context->ctx, sizeof(struct pt_regs));

    uint64_t sigrsp = f->rsp;

    sigrsp -= sizeof(void *);
    *((void **)sigrsp) = (void *)ptr->sa_restorer;

    current_task->arch_context->ctx->rip = (uint64_t)ptr->sa_handler;
    current_task->arch_context->ctx->rdi = sig;

    current_task->arch_context->ctx->cs = SELECTOR_USER_CS;
    current_task->arch_context->ctx->ss = SELECTOR_USER_DS;
    current_task->arch_context->ctx->ds = SELECTOR_USER_DS;
    current_task->arch_context->ctx->es = SELECTOR_USER_DS;
    current_task->arch_context->fs = SELECTOR_USER_DS;
    current_task->arch_context->gs = SELECTOR_USER_DS;

    current_task->arch_context->ctx->rsp = sigrsp;
#elif defined(__aarch64__)
#elif defined(__riscv)
#elif defined(__loongarch64)
#endif

    if (ptr->sa_flags & SIG_ONESHOT)
    {
        ptr->sa_handler = SIG_DFL;
    }

    current_task->call_in_signal = true;

    current_task->blocked |= ptr->sa_mask;

    spin_unlock(&signal_lock);

    arch_switch_with_context(NULL, current_task->arch_context, current_task->kernel_stack);
}
