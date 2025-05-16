#include <task/task.h>
#include <task/signal.h>
#include <arch/arch.h>

typedef struct signal_frame
{
    uint64_t restorer;
    uint64_t sig;
    uint64_t blocked;

    arch_signal_frame_t arch;
} __attribute__((packed)) signal_frame_t;

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
    for (int i = 1; i <= MAXSIG; i++)
    {
        if (!(unblocked_list & SIGMASK(i)))
            continue;
        sigaction_t *action = &task->actions[i - 1];
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
        safe &= ~(SIGKILL | SIGSTOP); // nuh uh!
        switch (how)
        {
        case SIG_BLOCK:
            current_task->blocked |= safe;
            break;
        case SIG_UNBLOCK:
            current_task->blocked &= ~safe;
            break;
        case SIG_SETMASK:
            current_task->blocked = safe;
            break;
        default:
            return -ENOSYS;
            break;
        }
    }

    return 0;
}

int sys_signal(int sig, uint64_t handler, uint64_t restorer)
{
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL)
    {
        return 0;
    }

    sigaction_t *ptr = &current_task->actions[sig - 1];
    ptr->sa_mask = 0;
    ptr->sa_handler = (sighandler_t)handler;
    ptr->sa_flags = SIG_ONESHOT | SIG_NOMASK;
    ptr->sa_restorer = (void (*)(void))restorer;
    return handler;
}

int sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction)
{
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL)
    {
        return 0;
    }

    sigaction_t *ptr = &current_task->actions[sig - 1];
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

void sys_sigreturn()
{
#if defined(__x86_64__)
    current_task->arch_context->ctx->cs = SELECTOR_USER_CS;
    current_task->arch_context->ctx->ss = SELECTOR_USER_DS;
    current_task->arch_context->ctx->ds = SELECTOR_USER_DS;
    current_task->arch_context->ctx->es = SELECTOR_USER_DS;
    struct pt_regs *ucontext = (struct pt_regs *)current_task->syscall_stack;
    current_task->arch_context->ctx->rax = ucontext->rax;
    current_task->arch_context->ctx->rflags = ucontext->r11;
    current_task->arch_context->ctx->rip = ucontext->rcx;

    arch_switch_with_context(NULL, current_task->arch_context, current_task->kernel_stack);
#endif
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
                tasks[i]->signal |= SIGMASK(sig);
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
        task_unblock(task, -SIGKILL);
    }

    return 0;
}

void sys_sendsignal(uint64_t pid, int sig)
{
    task_t *task = tasks[pid];
    task->signal |= SIGMASK(sig);
}

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

    sigaction_t *ptr = &current_task->actions[sig - 1];

    if (ptr->sa_handler == SIG_IGN)
    {
        return;
    }

    if (ptr->sa_handler == SIG_DFL)
    {
        return;
    }

#if defined(__x86_64__)
    struct pt_regs *iframe = current_task->arch_context->ctx;

    signal_frame_t *frame = (signal_frame_t *)iframe->rsp - 1;

    frame->arch.rax = iframe->rax;

    frame->arch.rbp = iframe->rbp;
    frame->arch.rdi = iframe->rdi;
    frame->arch.rsi = iframe->rsi;

    frame->arch.rbx = iframe->rbx;
    frame->arch.rcx = iframe->rcx;
    frame->arch.rdx = iframe->rdx;

    frame->arch.r8 = iframe->r8;
    frame->arch.r9 = iframe->r9;
    frame->arch.r10 = iframe->r10;
    frame->arch.r11 = iframe->r11;
    frame->arch.r12 = iframe->r12;
    frame->arch.r13 = iframe->r13;
    frame->arch.r14 = iframe->r14;
    frame->arch.r15 = iframe->r15;

    frame->arch.rip = iframe->rip;

    iframe->rsp = (uint64_t)frame;
    iframe->rip = (uint64_t)ptr->sa_handler;
#elif defined(__aarch64__)
    struct pt_regs *cframe = current_task->arch_context->ctx;

    signal_frame_t *frame = (signal_frame_t *)cframe - 1;
#elif defined(__riscv)
#elif defined(__loongarch64)
#endif

    frame->blocked = 0;

    if (ptr->sa_flags & SIG_NOMASK)
    {
        frame->blocked = current_task->blocked;
    }

    frame->sig = sig;
    frame->restorer = (uint64_t)ptr->sa_restorer;

    if (ptr->sa_flags & SIG_ONESHOT)
    {
        ptr->sa_handler = SIG_DFL;
    }

    current_task->blocked |= ptr->sa_mask;
}
