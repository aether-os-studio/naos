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

    uint64_t sigrsp = regs->rsp;

    struct sigcontext *ucontext = (struct sigcontext *)sigrsp;

    int signal = ucontext->reserved1[0];
    sigaction_t *action = &current_task->actions[signal];
    int flags = action->sa_flags;

    struct pt_regs *context = (struct pt_regs *)current_task->kernel_stack - 1;

    context->r8 = ucontext->arch.r8;
    context->r9 = ucontext->arch.r9;
    context->r10 = ucontext->arch.r10;
    context->r11 = ucontext->arch.r11;
    context->r12 = ucontext->arch.r12;
    context->r13 = ucontext->arch.r13;
    context->r14 = ucontext->arch.r14;
    context->r15 = ucontext->arch.r15;
    context->rdi = ucontext->arch.rdi;
    context->rsi = ucontext->arch.rsi;
    context->rbp = ucontext->arch.rbp;
    context->rbx = ucontext->arch.rbx;
    context->rdx = ucontext->arch.rdx;
    context->rcx = ucontext->arch.rcx;
    context->rax = ucontext->arch.rax;
    context->rsp = ucontext->arch.rsp;
    context->rip = ucontext->arch.rip;
    context->rflags = ucontext->arch.eflags;

    context->cs = ucontext->arch.cs;
    context->ss = ucontext->arch.ss;
    context->ds = ucontext->arch.ss;
    context->es = ucontext->arch.ss;
    current_task->arch_context->fs = ucontext->arch.fs;
    current_task->arch_context->gs = ucontext->arch.gs;

    if (ucontext->arch.fpstate)
    {
        memcpy(current_task->arch_context->fpu_ctx,
               ucontext->arch.fpstate,
               sizeof(struct fpstate));
    }

    current_task->arch_context->ctx = context;

    spin_unlock(&sigreturn_lock);

    current_task->call_in_signal = false;

    asm volatile(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(current_task->arch_context->ctx));
#elif defined(__aarch64__)
#else
    // todo: other architectures
    return NULL;
#endif
}

int sys_sigsuspend(const sigset_t *mask)
{
    sigset_t old = current_task->blocked;

    current_task->blocked = *mask;

    while (!signals_pending_quick(current_task))
    {
        arch_enable_interrupt();
        arch_pause();
    }
    arch_disable_interrupt();

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

    if (task->ppid != 0 && task->ppid != task->pid)
    {
        task_t *parent = tasks[task->ppid];
        if (!parent)
        {
            return 0;
        }

        parent->signal |= SIGMASK(SIGCHLD);

        if (parent->state == TASK_BLOCKING)
        {
            task_unblock(parent, -SIGCHLD);
        }
    }

    task->signal |= SIGMASK(sig);

    if (task->state == TASK_BLOCKING)
    {
        task_unblock(task, -sig);
    }

    return 0;
}

extern int signalfdfs_id;

void task_signal()
{
    arch_disable_interrupt();

    uint64_t map = current_task->signal & (~current_task->blocked);
    if (!map)
        return;

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
        return;
    }

    if (ptr->sa_handler == SIG_DFL)
    {
        return;
    }

#if defined(__x86_64__)
    struct pt_regs *f = (struct pt_regs *)current_task->syscall_stack - 1;

    uint64_t sigrsp = f->rsp;

    sigrsp -= 128;
    sigrsp -= DEFAULT_PAGE_SIZE;
    sigrsp = (sigrsp / DEFAULT_PAGE_SIZE) * DEFAULT_PAGE_SIZE;

    sigrsp -= sizeof(struct fpstate);
    struct fpstate *fpu = (struct fpstate *)sigrsp;
    memcpy(fpu, current_task->arch_context->fpu_ctx, sizeof(struct fpstate));

    sigrsp -= sizeof(struct sigcontext);
    struct sigcontext *ucontext = (struct sigcontext *)sigrsp;

    struct pt_regs *iframe = (struct pt_regs *)current_task->arch_context->ctx;

    ucontext->arch.r8 = iframe->r8;
    ucontext->arch.r9 = iframe->r9;
    ucontext->arch.r10 = iframe->r10;
    ucontext->arch.r11 = iframe->r11;
    ucontext->arch.r12 = iframe->r12;
    ucontext->arch.r13 = iframe->r13;
    ucontext->arch.r14 = iframe->r14;
    ucontext->arch.r15 = iframe->r15;
    ucontext->arch.rdi = iframe->rdi;
    ucontext->arch.rsi = iframe->rsi;
    ucontext->arch.rbp = iframe->rbp;
    ucontext->arch.rbx = iframe->rbx;
    ucontext->arch.rdx = iframe->rdx;
    ucontext->arch.rax = iframe->rax;
    ucontext->arch.rcx = iframe->rcx;
    ucontext->arch.rsp = iframe->rsp;
    ucontext->arch.cs = iframe->cs;
    ucontext->arch.ss = iframe->ss;
    ucontext->arch.fs = current_task->arch_context->fs;
    ucontext->arch.gs = current_task->arch_context->gs;
    ucontext->arch.rip = iframe->rip;
    ucontext->arch.eflags = iframe->rflags;
    ucontext->arch.err = 0;
    ucontext->arch.trapno = 0;
    ucontext->arch.oldmask = 0;
    ucontext->arch.cr2 = 0x1234567887654321;
    ucontext->arch.fpstate = 0;
    memset(ucontext->reserved1, 0, sizeof(ucontext->reserved1));

    ucontext->arch.oldmask = current_task->blocked;
    ucontext->arch.fpstate = fpu;
    ucontext->reserved1[0] = sig;

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

    arch_switch_with_context(NULL, current_task->arch_context, current_task->kernel_stack);
}
