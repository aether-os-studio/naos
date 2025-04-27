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

// 获取信号屏蔽位图
int sys_sgetmask()
{
    return current_task->blocked;
}

// 设置信号屏蔽位图
int sys_ssetmask(int newmask)
{
    if (newmask == 0)
    {
        return -1;
    }

    int old = current_task->blocked;
    current_task->blocked = newmask & ~SIGMASK(SIGKILL);

    return old;
}

int sys_signal(int sig, uint64_t handler, uint64_t restorer)
{
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL)
    {
        return 0;
    }

    sigaction_t *ptr = &current_task->actions[sig - 1];
    ptr->mask = 0;
    ptr->handler = (void (*)(int))handler;
    ptr->flags = SIG_ONESHOT | SIG_NOMASK;
    ptr->restorer = (void (*)(void))restorer;
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

    *ptr = *action;

    if (ptr->flags & SIG_NOMASK)
    {
        ptr->mask = 0;
    }
    else
    {
        ptr->mask |= SIGMASK(sig);
    }

    return 0;
}

int sys_kill(int pid, int sig)
{
    if (sig < MINSIG || sig > MAXSIG)
    {
        return 0;
    }

    task_t *task = get_task(pid);

    if (!task)
    {
        return 0;
    }

    task->signal |= SIGMASK(sig);

    if (task->state == TASK_BLOCKING)
    {
        task_unblock(task, -EINTR);
    }

    return 0;
}

void sys_sendsignal(uint64_t pid, int sig)
{
    task_t *task = get_task(pid);
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

    if (ptr->handler == SIG_IGN)
    {
        return;
    }

    if (ptr->handler == SIG_DFL)
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
    iframe->rip = (uint64_t)ptr->handler;
    iframe->rdi = (uint64_t)ptr->arg;
#elif defined(__aarch64__)
#elif defined(__riscv)
#elif defined(__loongarch64)
#endif

    frame->blocked = 0;

    if (ptr->flags & SIG_NOMASK)
    {
        frame->blocked = current_task->blocked;
    }

    frame->sig = sig;
    frame->restorer = (uint64_t)ptr->restorer;

    if (ptr->flags & SIG_ONESHOT)
    {
        ptr->handler = SIG_DFL;
    }

    current_task->blocked |= ptr->mask;
}
