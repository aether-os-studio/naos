#include <arch/arch.h>
#include <task/signal.h>
#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

#define SI_MAX_SIZE 128

signal_internal_t signal_internal_decisions[MAXSIG] = {0};

static inline sigset_t sigset_user_to_kernel(sigset_t user_mask) {
    sigset_t k = user_mask << 1;
    k &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP));
    return k;
}

static inline sigset_t sigset_kernel_to_user(sigset_t kernel_mask) {
    return kernel_mask >> 1;
}

#if defined(__x86_64__)
enum {
    X64_REG_R8 = 0,
    X64_REG_R9,
    X64_REG_R10,
    X64_REG_R11,
    X64_REG_R12,
    X64_REG_R13,
    X64_REG_R14,
    X64_REG_R15,
    X64_REG_RDI,
    X64_REG_RSI,
    X64_REG_RBP,
    X64_REG_RBX,
    X64_REG_RDX,
    X64_REG_RAX,
    X64_REG_RCX,
    X64_REG_RSP,
    X64_REG_RIP,
    X64_REG_EFL,
    X64_REG_CSGSFS,
    X64_REG_ERR,
    X64_REG_TRAPNO,
    X64_REG_OLDMASK,
    X64_REG_CR2,
};

static inline uint64_t signal_x64_frame_rsp(uint64_t user_rsp,
                                            uint64_t frame_size) {
    uint64_t sp = user_rsp - 128;
    sp = (sp - frame_size) & ~0xFUL;
    return sp - sizeof(void *);
}

static inline void signal_x64_fill_ucontext(ucontext_t *ucontext,
                                            const struct pt_regs *regs,
                                            uint64_t fpregs_addr,
                                            uint64_t flags,
                                            sigset_t blocked_mask) {
    memset(ucontext, 0, sizeof(*ucontext));

    ucontext->uc_flags = flags;
    ucontext->uc_link = NULL;
    ucontext->uc_mcontext.fpregs = (fpu_context_t *)fpregs_addr;

    ucontext->uc_mcontext.gregs[X64_REG_R8] = regs->r8;
    ucontext->uc_mcontext.gregs[X64_REG_R9] = regs->r9;
    ucontext->uc_mcontext.gregs[X64_REG_R10] = regs->r10;
    ucontext->uc_mcontext.gregs[X64_REG_R11] = regs->r11;
    ucontext->uc_mcontext.gregs[X64_REG_R12] = regs->r12;
    ucontext->uc_mcontext.gregs[X64_REG_R13] = regs->r13;
    ucontext->uc_mcontext.gregs[X64_REG_R14] = regs->r14;
    ucontext->uc_mcontext.gregs[X64_REG_R15] = regs->r15;
    ucontext->uc_mcontext.gregs[X64_REG_RDI] = regs->rdi;
    ucontext->uc_mcontext.gregs[X64_REG_RSI] = regs->rsi;
    ucontext->uc_mcontext.gregs[X64_REG_RBP] = regs->rbp;
    ucontext->uc_mcontext.gregs[X64_REG_RBX] = regs->rbx;
    ucontext->uc_mcontext.gregs[X64_REG_RDX] = regs->rdx;
    ucontext->uc_mcontext.gregs[X64_REG_RAX] = regs->rax;
    ucontext->uc_mcontext.gregs[X64_REG_RCX] = regs->rcx;
    ucontext->uc_mcontext.gregs[X64_REG_RSP] = regs->rsp;
    ucontext->uc_mcontext.gregs[X64_REG_RIP] = regs->rip;
    ucontext->uc_mcontext.gregs[X64_REG_EFL] = regs->rflags;
    ucontext->uc_mcontext.gregs[X64_REG_CSGSFS] =
        (regs->cs & 0xFFFFUL) | ((regs->ss & 0xFFFFUL) << 48);
    ucontext->uc_mcontext.gregs[X64_REG_ERR] = regs->errcode;
    ucontext->uc_mcontext.gregs[X64_REG_TRAPNO] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_OLDMASK] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_CR2] = 0;

    ucontext->uc_sigmask = sigset_kernel_to_user(blocked_mask);
}

#endif

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

extern int signalfdfs_id;

void task_commit_signal(task_t *task, int sig, siginfo_t *info) {
    spin_lock(&task->signal->signal_lock);
    pending_signal_t signal;
    memset(&signal, 0, sizeof(pending_signal_t));
    signal.sig = sig;
    if (info) {
        memcpy(&signal.info, info, sizeof(siginfo_t));
    } else {
        memset(&signal.info, 0, sizeof(siginfo_t));
        signal.info.si_signo = sig;
        signal.info.si_code = SI_KERNEL;
    }
    memcpy(&task->signal->pending_signal, &signal, sizeof(pending_signal_t));
    task->signal->pending_signal.processed = false;
    spin_unlock(&task->signal->signal_lock);
}

// 设置信号屏蔽位图
uint64_t sys_ssetmask(int how, const sigset_t *nset, sigset_t *oset,
                      size_t sigsetsize) {
    if (sigsetsize < sizeof(uint32_t) || sigsetsize > sizeof(uint64_t)) {
        return -EINVAL;
    }
    if (oset) {
        *oset = sigset_kernel_to_user(current_task->signal->blocked);
    }
    if (nset) {
        sigset_t safe = sigset_user_to_kernel(*nset);
        switch (how) {
        case SIG_BLOCK:
            current_task->signal->blocked |= safe;
            break;
        case SIG_UNBLOCK:
            current_task->signal->blocked &= ~(safe);
            break;
        case SIG_SETMASK:
            current_task->signal->blocked = safe;
            break;
        default:
            return -EINVAL;
            break;
        }
    }

    return 0;
}

uint64_t sys_sigprocmask(int how, const sigset_t *nset_u, sigset_t *oset_u,
                         size_t sigsetsize) {
    if (sigsetsize < sizeof(uint32_t) || sigsetsize > sizeof(uint64_t)) {
        return -EINVAL;
    }
    sigset_t nset = 0;
    sigset_t oset = 0;
    if (nset_u && copy_from_user(&nset, nset_u, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }
    uint64_t ret = sys_ssetmask(how, nset_u ? &nset : NULL,
                                oset_u ? &oset : NULL, sigsetsize);
    if (oset_u && copy_to_user(oset_u, &oset, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }
    return ret;
}

uint64_t sys_sigaction(int sig, const sigaction_t *action,
                       sigaction_t *oldaction) {
    if (sig < MINSIG || sig > MAXSIG || sig == SIGKILL || sig == SIGSTOP) {
        return -EINVAL;
    }

    spin_lock(&current_task->signal->signal_lock);
    sigaction_t *ptr = &current_task->signal->actions[sig];
    if (oldaction) {
        *oldaction = *ptr;
        oldaction->sa_mask = sigset_kernel_to_user(ptr->sa_mask);
    }

    if (action) {
        *ptr = *action;
        ptr->sa_mask = sigset_user_to_kernel(action->sa_mask);
    }
    spin_unlock(&current_task->signal->signal_lock);

    return 0;
}

uint64_t sys_sigreturn(struct pt_regs *regs) {
    arch_disable_interrupt();

    task_t *self = current_task;

    uint64_t tmp = self->syscall_stack;
    self->syscall_stack = self->signal_syscall_stack;
    self->signal_syscall_stack = tmp;

#if defined(__x86_64__)
    ucontext_t frame_ucontext;
    if (copy_from_user(&frame_ucontext, (void *)regs->rsp,
                       sizeof(frame_ucontext))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    memcpy(regs, &self->signal->signal_saved_ctx, sizeof(struct pt_regs));

    if (!frame_ucontext.uc_mcontext.fpregs ||
        copy_from_user(self->arch_context->fpu_ctx,
                       frame_ucontext.uc_mcontext.fpregs,
                       sizeof(fpu_context_t))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    self->signal->blocked = sigset_user_to_kernel(frame_ucontext.uc_sigmask);

    regs->rflags |= (1 << 9);
    regs->r11 = regs->rflags;
    regs->rcx = regs->rip;

    return regs->rax;

#elif defined(__aarch64__)
    return (uint64_t)-ENOSYS;
#elif defined(__loongarch64)
    return (uint64_t)-ENOSYS;
#else
    // todo: other architectures
    return (uint64_t)-ENOSYS;
#endif
}

uint64_t sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                             const struct timespec *uts, size_t sigsetsize) {
    if (sigsetsize < sizeof(uint32_t) || sigsetsize > sizeof(uint64_t)) {
        return -EINVAL;
    }

    sigset_t wait_mask = sigset_user_to_kernel(*uthese);

    uint64_t start = nano_time();
    uint64_t wait_ns = UINT64_MAX;
    if (uts) {
        wait_ns = uts->tv_sec * 1000000000ULL + uts->tv_nsec;
    }

    int sig = 0;
    while ((nano_time() - start < wait_ns || wait_ns == UINT64_MAX)) {
        if (current_task->signal->pending_signal.sig != 0) {
            int psig = current_task->signal->pending_signal.sig;
            if (wait_mask & SIGMASK(psig)) {
                sig = psig;
                break;
            }
        }

        sigset_t pending_list = current_task->signal->signal & wait_mask;
        if (pending_list) {
            for (int i = MINSIG; i <= MAXSIG; i++) {
                if (!(pending_list & SIGMASK(i)))
                    continue;
                sigaction_t *action = &current_task->signal->actions[i];
                sighandler_t user_handler = action->sa_handler;
                if (user_handler == SIG_IGN) {
                    current_task->signal->signal &= (~SIGMASK(i));
                    continue;
                }
                if (user_handler == SIG_DFL &&
                    signal_internal_decisions[i] == SIGNAL_INTERNAL_IGN) {
                    current_task->signal->signal &= (~SIGMASK(i));
                    continue;
                }
                current_task->signal->signal &= (~SIGMASK(i));
                sig = i;
                break;
            }
            if (sig != 0)
                break;
        }

        schedule(SCHED_FLAG_YIELD);
    }

    if (sig == 0) {
        return -EAGAIN;
    }

    if (current_task->signal->pending_signal.sig == sig) {
        if (uinfo) {
            memcpy(uinfo, &current_task->signal->pending_signal.info,
                   sizeof(siginfo_t));
        }
        current_task->signal->pending_signal.sig = 0;
    } else if (uinfo) {
        memset(uinfo, 0, sizeof(siginfo_t));
        uinfo->si_signo = sig;
        uinfo->si_errno = 0;
        uinfo->si_code = 0;
    }

    return sig;
}

uint64_t sys_rt_sigqueueinfo(uint64_t tgid, uint64_t sig, siginfo_t *info) {
    if (sig < MINSIG || sig > MAXSIG) {
        return -EINVAL;
    }
    if (tgid >= MAX_TASK_NUM) {
        return -EINVAL;
    }
    task_t *task = tasks[tgid];
    if (!task) {
        return -ESRCH;
    }
    siginfo_t kinfo;
    if (copy_from_user(&kinfo, info, sizeof(siginfo_t))) {
        return -EFAULT;
    }
    if (task->signal->pending_signal.sig != 0) {
        return -EAGAIN;
    }
    task_commit_signal(task, sig, &kinfo);
    return 0;
}

uint64_t sys_sigsuspend(const sigset_t *mask, size_t sigsetsize) {
    if (sigsetsize < sizeof(uint32_t) || sigsetsize > sizeof(uint64_t)) {
        return -EINVAL;
    }
    sigset_t old = current_task->signal->blocked;

    sigset_t mask_k;
    if (copy_from_user(&mask_k, mask, sigsetsize)) {
        return -EFAULT;
    }

    current_task->signal->blocked = mask_k;

    while (true) {
        schedule(SCHED_FLAG_YIELD);
    }

    current_task->signal->blocked = old;

    return -EINTR;
}

void task_fill_siginfo(siginfo_t *info, int sig, int code) {
    memset(info, 0, sizeof(siginfo_t));
    info->si_signo = sig;
    info->si_errno = 0;
    info->si_code = code;
    info->__si_fields.__kill.si_pid = current_task->pid;
    info->__si_fields.__kill.si_uid = current_task->uid;
}

void task_send_signal(task_t *task, int sig, int code) {
    if (!task)
        return;
    siginfo_t info;
    task_fill_siginfo(&info, sig, code);
    task_commit_signal(task, sig, &info);

    for (int i = 0; i < MAX_FD_NUM; i++) {
        fd_t *fd = task->fd_info->fds[i];
        if (fd) {
            vfs_node_t node = fd->node;
            if (node && node->fsid == signalfdfs_id) {
                struct signalfd_ctx *ctx = node->handle;
                if (ctx) {
                    struct signalfd_siginfo sinfo;
                    memset(&sinfo, 0, sizeof(struct signalfd_siginfo));
                    sinfo.ssi_signo = sig;
                    sinfo.ssi_code = code;

                    memcpy(&ctx->queue[ctx->queue_head], &sinfo,
                           sizeof(struct signalfd_siginfo));
                    ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_size;
                    if (ctx->queue_head == ctx->queue_tail) {
                        ctx->queue_tail =
                            (ctx->queue_tail + 1) % ctx->queue_size;
                    }
                }
            }
        }
    }

    if (sig != SIGSTOP && sig != SIGTSTP && sig != SIGTTIN && sig != SIGTTOU) {
        task_unblock(task, 128 + sig);
    }
}

static inline int task_effective_tgid(task_t *task) {
    if (!task) {
        return -1;
    }

    return task->tgid > 0 ? task->tgid : task->pid;
}

uint64_t sys_kill(int pid, int sig) {
    if (sig < 0 || sig > MAXSIG) {
        return -EINVAL;
    }
    if (sig == 0) {
        if (pid > 0) {
            return tasks[pid] ? 0 : -ESRCH;
        }
        if (pid == 0) {
            int pgid = current_task->pgid;
            for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
                task_t *task = tasks[i];
                if (task && task->pgid == pgid)
                    return 0;
            }
            return -ESRCH;
        }
        if (pid == -1) {
            for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
                task_t *task = tasks[i];
                if (task && !task->is_kernel)
                    return 0;
            }
            return -ESRCH;
        }
        int pgid = -pid;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            task_t *task = tasks[i];
            if (task && task->pgid == pgid)
                return 0;
        }
        return -ESRCH;
    }

    if (pid < 0) {
        if (pid == -1) {
            for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
                task_t *task = tasks[i];
                if (!task || task->is_kernel)
                    continue;
                task_send_signal(task, sig, SI_USER);
            }
            return 0;
        }

        int pgid = -pid;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            task_t *task = tasks[i];
            if (!task || task->is_kernel)
                continue;
            if (task->pgid == pgid) {
                task_send_signal(task, sig, SI_USER);
            }
        }
        return 0;
    }

    if (pid == 0) {
        int pgid = current_task->pgid;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            task_t *task = tasks[i];
            if (!task || task->is_kernel)
                continue;
            if (task->pgid == pgid) {
                task_send_signal(task, sig, SI_USER);
            }
        }
        return 0;
    }

    task_t *task = tasks[pid];

    if (!task) {
        return -ESRCH;
    }

    task_send_signal(task, sig, SI_USER);
    return 0;
}

uint64_t sys_tgkill(int tgid, int pid, int sig) {
    if (tgid <= 0 || pid <= 0 || sig < 0 || sig > MAXSIG) {
        return -EINVAL;
    }
    if (pid >= MAX_TASK_NUM) {
        return -ESRCH;
    }

    task_t *task = tasks[pid];
    if (!task) {
        return -ESRCH;
    }

    if (task_effective_tgid(task) != tgid) {
        return -ESRCH;
    }

    if (sig == 0) {
        return 0;
    }

    task_send_signal(task, sig, SI_TKILL);

    return 0;
}

void task_signal(struct pt_regs *regs) {
    task_t *self = current_task;

    if ((self->signal->pending_signal.sig == 0) || self->is_kernel ||
        self->arch_context->dead || self->signal->pending_signal.processed ||
        (self->state == TASK_DIED) || (self->state == TASK_UNINTERRUPTABLE)) {
        return;
    }

#if defined(__x86_64__)
    if (!regs || ((regs->cs & 0x3) != 0x3)) {
        return;
    }
#endif

    int psig = self->signal->pending_signal.sig;

    uint64_t map = SIGMASK(psig) & (~self->signal->blocked);
    if (psig == SIGKILL || psig == SIGSTOP)
        map = SIGMASK(psig);
    if (!map) {
        return;
    }

    spin_lock(&self->signal->signal_lock);
    int sig = psig;
    self->signal->signal |= SIGMASK(sig);
    self->signal->pending_signal.sig = 0;

    if (sig == SIGKILL) {
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + sig);
        return;
    }

    sigaction_t *ptr = &self->signal->actions[sig];

    if (ptr->sa_handler == SIG_IGN) {
        self->signal->signal &= ~SIGMASK(sig);
        spin_unlock(&self->signal->signal_lock);
        return;
    }

    if ((ptr->sa_handler == SIG_DFL) &&
        signal_internal_decisions[sig] == SIGNAL_INTERNAL_TERM) {
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + sig);
        return;
    }

    if ((ptr->sa_handler == SIG_DFL) &&
        signal_internal_decisions[sig] == SIGNAL_INTERNAL_CORE) {
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + sig);
        return;
    }

    if ((ptr->sa_handler == SIG_DFL) &&
        signal_internal_decisions[sig] == SIGNAL_INTERNAL_STOP) {
        self->signal->signal &= ~SIGMASK(sig);
        spin_unlock(&self->signal->signal_lock);
        return;
    }

    if ((ptr->sa_handler == SIG_DFL) &&
        signal_internal_decisions[sig] == SIGNAL_INTERNAL_CONT) {
        self->state = TASK_READY;
        self->signal->signal &= ~SIGMASK(sig);
        spin_unlock(&self->signal->signal_lock);
        return;
    }

    if (ptr->sa_handler == SIG_DFL) {
        self->signal->signal &= ~SIGMASK(sig);
        spin_unlock(&self->signal->signal_lock);
        return;
    }

    self->signal->signal &= ~SIGMASK(sig);

#if defined(__x86_64__)
    if (!(ptr->sa_flags & SA_RESTORER) || !ptr->sa_restorer) {
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + SIGSEGV);
        return;
    }

    siginfo_t frame_siginfo;
    memcpy(&frame_siginfo, &self->signal->pending_signal.info,
           sizeof(siginfo_t));
    memset(&self->signal->pending_signal.info, 0, sizeof(siginfo_t));

    uint64_t frame_size =
        sizeof(ucontext_t) + sizeof(siginfo_t) + sizeof(fpu_context_t);
    uint64_t frame_rsp = signal_x64_frame_rsp(regs->rsp, frame_size);

    uint64_t ucontext_addr = frame_rsp + sizeof(void *);
    uint64_t siginfo_addr = ucontext_addr + sizeof(ucontext_t);
    uint64_t fp_addr = siginfo_addr + sizeof(siginfo_t);

    memcpy(&self->signal->signal_saved_ctx, regs, sizeof(struct pt_regs));

    ucontext_t frame_ucontext;
    signal_x64_fill_ucontext(&frame_ucontext, regs, fp_addr, ptr->sa_flags,
                             self->signal->blocked);
    frame_ucontext.uc_link = NULL;

    void *frame_restorer = (void *)ptr->sa_restorer;
    if (copy_to_user((void *)fp_addr, self->arch_context->fpu_ctx,
                     sizeof(fpu_context_t)) ||
        copy_to_user((void *)siginfo_addr, &frame_siginfo, sizeof(siginfo_t)) ||
        copy_to_user((void *)ucontext_addr, &frame_ucontext,
                     sizeof(ucontext_t)) ||
        copy_to_user((void *)frame_rsp, &frame_restorer, sizeof(void *))) {
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + SIGSEGV);
        return;
    }

    memset(regs, 0, sizeof(struct pt_regs));

    regs->rip = (uint64_t)ptr->sa_handler;
    regs->rdi = sig;
    if (ptr->sa_flags & SA_SIGINFO) {
        regs->rsi = siginfo_addr;
        regs->rdx = ucontext_addr;
    }

    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;

    regs->rflags |= (1 << 9);
    regs->rsp = frame_rsp;
    regs->rbp = frame_rsp;
    regs->rcx = regs->rip;
    regs->r11 = regs->rflags;
#elif defined(__aarch64__)
#elif defined(__riscv)
    struct pt_regs *f = (struct pt_regs *)self->kernel_stack - 1;

    memcpy(&self->signal->signal_saved_regs, self->arch_context->ctx,
           sizeof(struct pt_regs));
#elif defined(__loongarch64)
#endif

    if (ptr->sa_flags & SA_RESETHAND) {
        ptr->sa_handler = SIG_DFL;
    }

    self->signal->blocked |= ptr->sa_mask;
    if (!(ptr->sa_flags & SA_NODEFER)) {
        self->signal->blocked |= SIGMASK(sig);
    }

    uint64_t tmp = self->syscall_stack;
    self->syscall_stack = self->signal_syscall_stack;
    self->signal_syscall_stack = tmp;

    spin_unlock(&self->signal->signal_lock);
}
