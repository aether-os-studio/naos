#include <arch/arch.h>
#include <task/signal.h>
#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

#define SI_MAX_SIZE 128

struct sigcontext {
    arch_signal_frame_t arch;
    uint64_t reserved1[8];
};

signal_internal_t signal_internal_decisions[MAXSIG] = {0};

void signal_init() {
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

int signals_pending_quick(task_t *task) {
    sigset_t pending_list = task->signal;
    sigset_t unblocked_list = pending_list & (~task->blocked);
    for (int i = MINSIG; i <= MAXSIG; i++) {
        if (!(unblocked_list & SIGMASK(i)))
            continue;
        sigaction_t *action = &task->actions[i];
        sighandler_t user_handler = action->sa_handler;
        if (user_handler == SIG_IGN)
            continue;
        if (user_handler == SIG_DFL &&
            signal_internal_decisions[i] == SIGNAL_INTERNAL_IGN)
            continue;

        task->signal &= (~SIGMASK(i));

        return i;
    }

    return 0;
}

// 获取信号屏蔽位图
uint64_t sys_sgetmask() { return current_task->blocked; }

// 设置信号屏蔽位图
uint64_t sys_ssetmask(int how, sigset_t *nset, sigset_t *oset) {
    if (oset)
        *oset = current_task->blocked >> 1;
    if (nset) {
        uint64_t safe = *nset;
        safe <<= 1;
        safe &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP)); // nuh uh!
        switch (how) {
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

uint64_t sys_sigaction(int sig, sigaction_t *action, sigaction_t *oldaction) {
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL) {
        return -EINVAL;
    }

    spin_lock(&current_task->signal_lock);
    sigaction_t *ptr = &current_task->actions[sig];
    if (oldaction) {
        *oldaction = *ptr;
    }

    if (action) {
        *ptr = *action;
    }
    spin_unlock(&current_task->signal_lock);

    return 0;
}

void sys_sigreturn(struct pt_regs *regs) {
    arch_disable_interrupt();

#if defined(__x86_64__)
    struct pt_regs *context = (struct pt_regs *)current_task->kernel_stack - 1;

    memcpy(context, &current_task->signal_saved_regs, sizeof(struct pt_regs));

    current_task->blocked = current_task->saved_blocked;
    current_task->saved_blocked = 0;

    current_task->arch_context->ctx = context;

    asm volatile(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(current_task->arch_context->ctx));
#elif defined(__aarch64__)
#elif defined(__loongarch64)
#else
    // todo: other architectures
#endif
}

uint64_t sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                             const struct timespec *uts, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t)) {
        return -EINVAL;
    }

    sigset_t old = current_task->blocked;

    current_task->blocked = *uthese;

    uint64_t start = nanoTime();
    uint64_t wait_ns = 0;
    if (uts) {
        wait_ns = uts->tv_sec * 1000000000ULL + uts->tv_nsec;
    }

    int sig = 0;
    while (!(sig = signals_pending_quick(current_task), sig) &&
           (nanoTime() - start < wait_ns || wait_ns == 0)) {
        arch_yield();
    }

    current_task->blocked = old;

    if (uinfo) {
        memset(uinfo, 0, sizeof(siginfo_t));
        uinfo->si_signo = sig;
        uinfo->si_errno = 0;
        uinfo->si_code = 0;
    }

    return 0;
}

uint64_t sys_sigsuspend(const sigset_t *mask) {
    sigset_t old = current_task->blocked;

    current_task->blocked = *mask;

    while (!signals_pending_quick(current_task)) {
        arch_enable_interrupt();
        arch_pause();
    }
    arch_disable_interrupt();

    current_task->blocked = old;

    return -EINTR;
}

uint64_t sys_kill(int pid, int sig) {
    if (sig < MINSIG || sig > MAXSIG) {
        return 0;
    }

    if (pid < 0) {
        for (uint64_t i = cpu_count; i < MAX_TASK_NUM; i++) {
            if (tasks[i] && tasks[i]->ppid == current_task->pid) {
                sys_kill(tasks[i]->pid, sig);
            }
        }

        return 0;
    }

    if (!pid) {
        return 0;
    }

    task_t *task = tasks[pid];

    if (!task) {
        return -ESRCH;
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
    //         parent->pending_signal |= SIGMASK(SIGCHLD);
    //     }

    //     if (parent->state == TASK_BLOCKING)
    //     {
    //         task_unblock(parent, SIGCHLD);
    //     }
    // }

    spin_lock(&task->signal_lock);
    task->pending_signal |= SIGMASK(sig);
    spin_unlock(&task->signal_lock);

    task_unblock(task, 128 + sig);

    return 0;
}

extern int signalfdfs_id;

void task_signal() {
    if (current_task->state == TASK_DIED || current_task->arch_context->dead ||
        current_task->state == TASK_UNINTERRUPTABLE) {
        return;
    }

    uint64_t map = current_task->pending_signal & (~current_task->blocked);
    if (!map) {
        return;
    }

    spin_lock(&current_task->signal_lock);
    int sig = 1;
    for (; sig <= MAXSIG; sig++) {
        if (map & SIGMASK(sig)) {
            current_task->signal |= SIGMASK(sig);
            current_task->pending_signal &= ~SIGMASK(sig);
            break;
        }
    }

    if (sig == SIGKILL) {
        spin_unlock(&current_task->signal_lock);
        task_exit(128 + sig);
        return;
    }

    // for (int i = 0; i < MAX_FD_NUM; i++) {
    //     if (current_task->fd_info->fds[i]) {
    //         vfs_node_t node = current_task->fd_info->fds[i]->node;
    //         if (node && node->fsid == signalfdfs_id) {
    //             struct signalfd_ctx *ctx = node->handle;

    //             struct signalfd_siginfo info;
    //             memset(&info, 0, sizeof(struct sigevent));
    //             info.ssi_signo = sig;

    //             memcpy(&ctx->queue[ctx->queue_head], &info,
    //                    sizeof(struct signalfd_siginfo));
    //             ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_size;
    //             if (ctx->queue_head == ctx->queue_tail) {
    //                 ctx->queue_tail = (ctx->queue_tail + 1) %
    //                 ctx->queue_size;
    //             }
    //         }
    //     }
    // }

    sigaction_t *ptr = &current_task->actions[sig];

    if (ptr->sa_handler == SIG_IGN) {
        spin_unlock(&current_task->signal_lock);
        return;
    }

    if (ptr->sa_handler == SIG_DFL) {
        spin_unlock(&current_task->signal_lock);
        return;
    }

    arch_disable_interrupt();

    current_task->state = TASK_UNINTERRUPTABLE;

#if defined(__x86_64__)
    struct pt_regs *f = (struct pt_regs *)current_task->syscall_stack - 1;

    memcpy(&current_task->signal_saved_regs, current_task->arch_context->ctx,
           sizeof(struct pt_regs));

    uint64_t sigrsp = f->rsp;

    sigrsp -= 128;

    sigrsp -= DEFAULT_PAGE_SIZE;
    sigrsp = sigrsp & ~(DEFAULT_PAGE_SIZE - 1);

    sigrsp -= sizeof(struct fpstate);
    struct fpstate *fp = (struct fpstate *)sigrsp;
    memcpy(fp, current_task->arch_context->fpu_ctx, sizeof(struct fpstate));

    sigrsp -= sizeof(arch_signal_frame_t);
    arch_signal_frame_t *sframe = (arch_signal_frame_t *)sigrsp;

    sframe->r8 = f->r8;
    sframe->r9 = f->r9;
    sframe->r10 = f->r10;
    sframe->r11 = f->r11;
    sframe->r12 = f->r12;
    sframe->r13 = f->r13;
    sframe->r14 = f->r14;
    sframe->r15 = f->r15;
    sframe->rdi = f->rdi;
    sframe->rsi = f->rsi;
    sframe->rbp = f->rbp;
    sframe->rbx = f->rbx;
    sframe->rdx = f->rdx;
    sframe->rax = f->rax;
    sframe->rcx = f->rcx;
    sframe->rsp = f->rsp;
    sframe->rip = f->rip;
    sframe->eflags = f->rflags;
    sframe->cs = f->cs;
    sframe->gs = 0;
    sframe->fs = 0;
    sframe->ss = f->ss;
    sframe->oldmask = current_task->blocked;
    sframe->fpstate = fp;
    sframe->reserved[0] = (uint64_t)sig;

    sigrsp -= sizeof(void *);
    *((void **)sigrsp) = (void *)ptr->sa_restorer;

    memset(current_task->arch_context->ctx, 0, sizeof(struct pt_regs));

    current_task->arch_context->ctx->rip = (uint64_t)ptr->sa_handler;
    current_task->arch_context->ctx->rdi = sig;

    current_task->arch_context->ctx->cs = SELECTOR_USER_CS;
    current_task->arch_context->ctx->ss = SELECTOR_USER_DS;

    current_task->arch_context->ctx->rflags = (1 << 9);
    current_task->arch_context->ctx->rsp = sigrsp;
#elif defined(__aarch64__)
#elif defined(__riscv)
    struct pt_regs *f = (struct pt_regs *)current_task->kernel_stack - 1;

    memcpy(&current_task->signal_saved_regs, current_task->arch_context->ctx,
           sizeof(struct pt_regs));
#elif defined(__loongarch64)
#endif

    if (ptr->sa_flags & SIG_ONESHOT) {
        ptr->sa_handler = SIG_DFL;
    }

    current_task->saved_blocked = current_task->blocked;
    current_task->blocked |= (1 << sig) | ptr->sa_mask;

    spin_unlock(&current_task->signal_lock);

    current_task->state = TASK_READY;

#if defined(__x86_64__)
    asm volatile(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(current_task->arch_context->ctx));
#elif defined(__aarch64__)
#elif defined(__riscv)
    asm volatile(
        "mv sp, %0\n\t"
        "j ret_from_trap_handler\n\t" ::"r"(current_task->arch_context->ctx));
#elif defined(__loongarch64)
#endif
}
