#include <arch/arch.h>
#include <task/signal.h>

#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

#if defined(__x86_64__)
#include <arch/x64/syscall/nr.h>
#endif

#define SIGNAL_MIN_SIGSET_SIZE sizeof(uint32_t)
#define SIGNAL_MAX_SIGSET_SIZE sizeof(sigset_t)
#define SIGNAL_MAX_MASKED_SIG ((int)(sizeof(sigset_t) * 8 - 1))

#if defined(__x86_64__)
#define SIGNAL_X64_SYSCALL_INS_LEN 2
#define SIGNAL_X64_MAX_SYSCALL_NR 1024

#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516
#endif

signal_internal_t signal_internal_decisions[MAXSIG] = {0};

extern int signalfdfs_id;

static inline bool signal_sig_in_range(int sig) {
    return sig >= MINSIG && sig < MAXSIG;
}

static inline bool signal_sig_maskable(int sig) {
    return sig >= MINSIG && sig <= SIGNAL_MAX_MASKED_SIG;
}

static inline bool signal_sigset_size_valid(size_t sigsetsize) {
    return sigsetsize >= SIGNAL_MIN_SIGSET_SIZE &&
           sigsetsize <= SIGNAL_MAX_SIGSET_SIZE;
}

static inline sigset_t signal_sigbit(int sig) {
    return (sigset_t)1ULL << (uint64_t)sig;
}

static inline sigset_t sigset_user_to_kernel(sigset_t user_mask) {
    sigset_t k = user_mask << 1;
    if (signal_sig_maskable(SIGKILL)) {
        k &= ~signal_sigbit(SIGKILL);
    }
    if (signal_sig_maskable(SIGSTOP)) {
        k &= ~signal_sigbit(SIGSTOP);
    }
    return k;
}

static inline sigset_t sigset_kernel_to_user(sigset_t kernel_mask) {
    return kernel_mask >> 1;
}

static inline bool signal_sigset_has(sigset_t set, int sig) {
    if (!signal_sig_maskable(sig)) {
        return false;
    }
    return (set & signal_sigbit(sig)) != 0;
}

static inline bool signal_is_blocked(sigset_t blocked, int sig) {
    if (sig == SIGKILL || sig == SIGSTOP) {
        return false;
    }
    return signal_sigset_has(blocked, sig);
}

static inline sigset_t signal_pending_mask_locked(task_t *task) {
    sigset_t pending = task->signal->signal;
    int pending_slot_sig = task->signal->pending_signal.sig;
    if (signal_sig_maskable(pending_slot_sig)) {
        pending |= signal_sigbit(pending_slot_sig);
    }
    return pending;
}

static inline void signal_fill_kernel_siginfo(siginfo_t *info, int sig,
                                              int code) {
    memset(info, 0, sizeof(*info));
    info->si_signo = sig;
    info->si_errno = 0;
    info->si_code = code;
}

static inline bool signal_action_ignored(int sig, const sigaction_t *action) {
    if (sig == SIGKILL || sig == SIGSTOP) {
        return false;
    }
    if (action->sa_handler == SIG_IGN) {
        return true;
    }
    if (action->sa_handler == SIG_DFL &&
        signal_internal_decisions[sig] == SIGNAL_INTERNAL_IGN) {
        return true;
    }
    return false;
}

static inline int signal_pick_from_set_locked(task_t *task, sigset_t set) {
    sigset_t pending = signal_pending_mask_locked(task) & set;
    for (int sig = MINSIG; sig <= SIGNAL_MAX_MASKED_SIG; sig++) {
        if (pending & signal_sigbit(sig)) {
            return sig;
        }
    }
    return 0;
}

static inline int signal_pick_deliverable_locked(task_t *task) {
    sigset_t pending = signal_pending_mask_locked(task);
    sigset_t blocked = task->signal->blocked;
    for (int sig = MINSIG; sig <= SIGNAL_MAX_MASKED_SIG; sig++) {
        if (!(pending & signal_sigbit(sig))) {
            continue;
        }
        if (!signal_is_blocked(blocked, sig)) {
            return sig;
        }
    }

    int pending_slot_sig = task->signal->pending_signal.sig;
    if (signal_sig_in_range(pending_slot_sig) &&
        !signal_sig_maskable(pending_slot_sig) &&
        !signal_is_blocked(blocked, pending_slot_sig)) {
        return pending_slot_sig;
    }

    return 0;
}

static inline void signal_take_pending_locked(task_t *task, int sig,
                                              siginfo_t *info) {
    if (signal_sig_maskable(sig)) {
        task->signal->signal &= ~signal_sigbit(sig);
    }

    if (task->signal->pending_signal.sig == sig) {
        memcpy(info, &task->signal->pending_signal.info, sizeof(*info));
        memset(&task->signal->pending_signal, 0,
               sizeof(task->signal->pending_signal));
        return;
    }

    signal_fill_kernel_siginfo(info, sig, SI_KERNEL);
}

static inline bool
signal_has_deliverable_outside_set_locked(task_t *task, sigset_t wait_set) {
    sigset_t pending = signal_pending_mask_locked(task);
    sigset_t blocked = task->signal->blocked;

    for (int sig = MINSIG; sig <= SIGNAL_MAX_MASKED_SIG; sig++) {
        if (!(pending & signal_sigbit(sig))) {
            continue;
        }
        if (signal_is_blocked(blocked, sig)) {
            continue;
        }
        if (wait_set & signal_sigbit(sig)) {
            continue;
        }
        sigaction_t *action = &task->signal->actions[sig];
        if (signal_action_ignored(sig, action)) {
            continue;
        }
        return true;
    }

    int pending_slot_sig = task->signal->pending_signal.sig;
    if (signal_sig_in_range(pending_slot_sig) &&
        !signal_sig_maskable(pending_slot_sig) &&
        !signal_is_blocked(blocked, pending_slot_sig)) {
        sigaction_t *action = &task->signal->actions[pending_slot_sig];
        if (!signal_action_ignored(pending_slot_sig, action)) {
            return true;
        }
    }

    return false;
}

static inline bool signal_arch_user_context(struct pt_regs *regs) {
    if (!regs) {
        return false;
    }

#if defined(__x86_64__)
    return (regs->cs & 0x3) == 0x3;
#elif defined(__aarch64__)
    return (regs->cpsr & 0xF) == 0;
#elif defined(__riscv__)
    return (regs->sstatus & (1ULL << 8)) == 0;
#elif defined(__loongarch64)
    return (regs->csr_prmd & 0x3) == 0;
#else
    return true;
#endif
}

static inline void signal_set_default(int sig, signal_internal_t action) {
    if (signal_sig_in_range(sig)) {
        signal_internal_decisions[sig] = action;
    }
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

static inline bool signal_x64_is_syscall_context(const struct pt_regs *regs) {
    return ((regs->cs & 0x3) == 0x3) && regs->rip == regs->rcx &&
           regs->rflags == regs->r11 && regs->func <= SIGNAL_X64_MAX_SYSCALL_NR;
}

static inline bool signal_x64_restartable_syscall(uint64_t nr) {
    switch (nr) {
    case SYS_PAUSE:
    case SYS_NANOSLEEP:
    case SYS_CLOCK_NANOSLEEP:
    case SYS_RT_SIGSUSPEND:
    case SYS_RT_SIGTIMEDWAIT:
    case SYS_PSELECT6:
    case SYS_PPOLL:
    case SYS_EPOLL_WAIT:
    case SYS_EPOLL_PWAIT:
    case SYS_EPOLL_PWAIT2:
        return false;
    default:
        return true;
    }
}

static inline void
signal_x64_prepare_syscall_result(struct pt_regs *saved,
                                  const sigaction_t *action) {
    if (!signal_x64_is_syscall_context(saved)) {
        return;
    }

    int64_t retval = (int64_t)saved->rax;
    if (retval >= 0) {
        return;
    }

    int64_t err = -retval;
    bool want_restart = false;
    bool force_eintr = false;

    switch (err) {
    case ERESTARTNOINTR:
        want_restart = true;
        break;
    case ERESTARTSYS:
    case ERESTART:
        want_restart = (action->sa_flags & SA_RESTART) != 0;
        force_eintr = !want_restart;
        break;
    case ERESTARTNOHAND:
    case ERESTART_RESTARTBLOCK:
        force_eintr = true;
        break;
    case EINTR:
        if (action->sa_flags & SA_RESTART) {
            want_restart = true;
        } else {
            force_eintr = true;
        }
        break;
    default:
        return;
    }

    if (want_restart) {
        uint64_t nr = saved->func;
        if (nr <= SIGNAL_X64_MAX_SYSCALL_NR &&
            signal_x64_restartable_syscall(nr)) {
            saved->rax = nr;
            if (saved->rip >= SIGNAL_X64_SYSCALL_INS_LEN) {
                saved->rip -= SIGNAL_X64_SYSCALL_INS_LEN;
            }
            return;
        }
        force_eintr = true;
    }

    if (force_eintr) {
        saved->rax = (uint64_t)-EINTR;
    }
}

static inline uint64_t signal_x64_frame_rsp(uint64_t user_rsp,
                                            uint64_t frame_size) {
    uint64_t sp = user_rsp - 128;
    sp = (sp - frame_size) & ~0xFULL;
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
        (regs->cs & 0xFFFFULL) | ((regs->ss & 0xFFFFULL) << 48);
    ucontext->uc_mcontext.gregs[X64_REG_ERR] = regs->errcode;
    ucontext->uc_mcontext.gregs[X64_REG_TRAPNO] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_OLDMASK] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_CR2] = 0;
    ucontext->uc_sigmask = sigset_kernel_to_user(blocked_mask);
}

static inline void signal_x64_restore_ptregs(struct pt_regs *regs,
                                             const ucontext_t *ucontext) {
    regs->r8 = ucontext->uc_mcontext.gregs[X64_REG_R8];
    regs->r9 = ucontext->uc_mcontext.gregs[X64_REG_R9];
    regs->r10 = ucontext->uc_mcontext.gregs[X64_REG_R10];
    regs->r11 = ucontext->uc_mcontext.gregs[X64_REG_R11];
    regs->r12 = ucontext->uc_mcontext.gregs[X64_REG_R12];
    regs->r13 = ucontext->uc_mcontext.gregs[X64_REG_R13];
    regs->r14 = ucontext->uc_mcontext.gregs[X64_REG_R14];
    regs->r15 = ucontext->uc_mcontext.gregs[X64_REG_R15];
    regs->rdi = ucontext->uc_mcontext.gregs[X64_REG_RDI];
    regs->rsi = ucontext->uc_mcontext.gregs[X64_REG_RSI];
    regs->rbp = ucontext->uc_mcontext.gregs[X64_REG_RBP];
    regs->rbx = ucontext->uc_mcontext.gregs[X64_REG_RBX];
    regs->rdx = ucontext->uc_mcontext.gregs[X64_REG_RDX];
    regs->rax = ucontext->uc_mcontext.gregs[X64_REG_RAX];
    regs->rcx = ucontext->uc_mcontext.gregs[X64_REG_RCX];
    regs->rsp = ucontext->uc_mcontext.gregs[X64_REG_RSP];
    regs->rip = ucontext->uc_mcontext.gregs[X64_REG_RIP];
    regs->rflags = ucontext->uc_mcontext.gregs[X64_REG_EFL];
    uint64_t csgsfs = ucontext->uc_mcontext.gregs[X64_REG_CSGSFS];
    regs->cs = csgsfs & 0xFFFFULL;
    regs->ss = (csgsfs >> 48) & 0xFFFFULL;
    regs->errcode = ucontext->uc_mcontext.gregs[X64_REG_ERR];
    regs->func = 0;

    if ((regs->cs & 0x3) != 0x3) {
        regs->cs = SELECTOR_USER_CS;
    }
    if ((regs->ss & 0x3) != 0x3) {
        regs->ss = SELECTOR_USER_DS;
    }
}

static bool signal_x64_setup_frame(task_t *task, struct pt_regs *regs, int sig,
                                   const sigaction_t *action,
                                   const siginfo_t *info) {
    if (!(action->sa_flags & SA_RESTORER) || !action->sa_restorer) {
        return false;
    }

    struct pt_regs saved = *regs;
    signal_x64_prepare_syscall_result(&saved, action);

    uint64_t frame_size =
        sizeof(ucontext_t) + sizeof(siginfo_t) + sizeof(fpu_context_t);
    uint64_t frame_rsp = signal_x64_frame_rsp(saved.rsp, frame_size);
    uint64_t ucontext_addr = frame_rsp + sizeof(void *);
    uint64_t siginfo_addr = ucontext_addr + sizeof(ucontext_t);
    uint64_t fp_addr = siginfo_addr + sizeof(siginfo_t);

    ucontext_t frame_ucontext;
    signal_x64_fill_ucontext(&frame_ucontext, &saved, fp_addr, action->sa_flags,
                             task->signal->blocked);

    void *frame_restorer = (void *)action->sa_restorer;
    if (copy_to_user((void *)fp_addr, task->arch_context->fpu_ctx,
                     sizeof(fpu_context_t)) ||
        copy_to_user((void *)siginfo_addr, info, sizeof(*info)) ||
        copy_to_user((void *)ucontext_addr, &frame_ucontext,
                     sizeof(frame_ucontext)) ||
        copy_to_user((void *)frame_rsp, &frame_restorer,
                     sizeof(frame_restorer))) {
        return false;
    }

    memset(regs, 0, sizeof(*regs));
    regs->rip = (uint64_t)action->sa_handler;
    regs->rdi = sig;
    if (action->sa_flags & SA_SIGINFO) {
        regs->rsi = siginfo_addr;
        regs->rdx = ucontext_addr;
    }
    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;
    regs->rflags = saved.rflags | (1ULL << 9);
    regs->rsp = frame_rsp;
    regs->rbp = frame_rsp;
    regs->rcx = regs->rip;
    regs->r11 = regs->rflags;

    return true;
}
#endif

void signal_init() {
    for (int i = 0; i < MAXSIG; i++) {
        signal_internal_decisions[i] = SIGNAL_INTERNAL_TERM;
    }

    signal_set_default(SIGABRT, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGBUS, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGCHLD, SIGNAL_INTERNAL_IGN);
    signal_set_default(SIGCONT, SIGNAL_INTERNAL_CONT);
    signal_set_default(SIGFPE, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGILL, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGIOT, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGQUIT, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGSEGV, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGSTOP, SIGNAL_INTERNAL_STOP);
    signal_set_default(SIGTSTP, SIGNAL_INTERNAL_STOP);
    signal_set_default(SIGSYS, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGTRAP, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGTTIN, SIGNAL_INTERNAL_STOP);
    signal_set_default(SIGTTOU, SIGNAL_INTERNAL_STOP);
    signal_set_default(SIGUNUSED, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGURG, SIGNAL_INTERNAL_IGN);
    signal_set_default(SIGWINCH, SIGNAL_INTERNAL_IGN);
    signal_set_default(SIGXCPU, SIGNAL_INTERNAL_CORE);
    signal_set_default(SIGXFSZ, SIGNAL_INTERNAL_CORE);
}

void task_commit_signal(task_t *task, int sig, siginfo_t *info) {
    if (!task || !task->signal || !signal_sig_in_range(sig)) {
        return;
    }

    siginfo_t kinfo;
    if (info) {
        memcpy(&kinfo, info, sizeof(kinfo));
    } else {
        signal_fill_kernel_siginfo(&kinfo, sig, SI_KERNEL);
    }
    kinfo.si_signo = sig;

    spin_lock(&task->signal->signal_lock);

    if (signal_sig_maskable(sig)) {
        task->signal->signal |= signal_sigbit(sig);
    }

    if (task->signal->pending_signal.sig == 0) {
        task->signal->pending_signal.sig = sig;
        memcpy(&task->signal->pending_signal.info, &kinfo, sizeof(kinfo));
    }

    task->signal->pending_signal.processed = false;

    spin_unlock(&task->signal->signal_lock);
}

uint64_t sys_ssetmask(int how, const sigset_t *nset, sigset_t *oset,
                      size_t sigsetsize) {
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }

    spin_lock(&current_task->signal->signal_lock);

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
            current_task->signal->blocked &= ~safe;
            break;
        case SIG_SETMASK:
            current_task->signal->blocked = safe;
            break;
        default:
            spin_unlock(&current_task->signal->signal_lock);
            return (uint64_t)-EINVAL;
        }
    }

    spin_unlock(&current_task->signal->signal_lock);
    return 0;
}

uint64_t sys_sigprocmask(int how, const sigset_t *nset_u, sigset_t *oset_u,
                         size_t sigsetsize) {
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }

    sigset_t nset = 0;
    sigset_t oset = 0;
    if (nset_u && copy_from_user(&nset, nset_u, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }

    uint64_t ret = sys_ssetmask(how, nset_u ? &nset : NULL,
                                oset_u ? &oset : NULL, sigsetsize);
    if ((int64_t)ret < 0) {
        return ret;
    }

    if (oset_u && copy_to_user(oset_u, &oset, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }

    return ret;
}

uint64_t sys_sigaction(int sig, const sigaction_t *action,
                       sigaction_t *oldaction) {
    if (!signal_sig_in_range(sig) || sig == SIGKILL || sig == SIGSTOP) {
        return (uint64_t)-EINVAL;
    }

    sigaction_t new_action;
    bool has_new = action != NULL;
    if (has_new) {
        if (copy_from_user(&new_action, action, sizeof(new_action))) {
            return (uint64_t)-EFAULT;
        }
        new_action.sa_mask = sigset_user_to_kernel(new_action.sa_mask);
#if defined(__x86_64__)
        if (new_action.sa_handler != SIG_DFL &&
            new_action.sa_handler != SIG_IGN &&
            ((new_action.sa_flags & SA_RESTORER) == 0 ||
             new_action.sa_restorer == NULL)) {
            return (uint64_t)-EINVAL;
        }
#endif
    }

    sigaction_t old_local;
    bool has_old = oldaction != NULL;

    spin_lock(&current_task->signal->signal_lock);
    sigaction_t *slot = &current_task->signal->actions[sig];
    if (has_old) {
        old_local = *slot;
        old_local.sa_mask = sigset_kernel_to_user(old_local.sa_mask);
    }
    if (has_new) {
        *slot = new_action;
    }
    spin_unlock(&current_task->signal->signal_lock);

    if (has_old && copy_to_user(oldaction, &old_local, sizeof(old_local))) {
        return (uint64_t)-EFAULT;
    }

    return 0;
}

uint64_t sys_sigreturn(struct pt_regs *regs) {
#if defined(__x86_64__)
    arch_disable_interrupt();

    task_t *self = current_task;
    if (!self || !regs) {
        return (uint64_t)-EFAULT;
    }

    ucontext_t frame_ucontext;
    if (copy_from_user(&frame_ucontext, (void *)regs->rsp,
                       sizeof(frame_ucontext))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    if (frame_ucontext.uc_mcontext.fpregs &&
        copy_from_user(self->arch_context->fpu_ctx,
                       frame_ucontext.uc_mcontext.fpregs,
                       sizeof(fpu_context_t))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_x64_restore_ptregs(regs, &frame_ucontext);

    spin_lock(&self->signal->signal_lock);
    self->signal->blocked = sigset_user_to_kernel(frame_ucontext.uc_sigmask);
    spin_unlock(&self->signal->signal_lock);

    uint64_t tmp = self->syscall_stack;
    self->syscall_stack = self->signal_syscall_stack;
    self->signal_syscall_stack = tmp;

    regs->rflags |= (1ULL << 9);
    regs->r11 = regs->rflags;
    regs->rcx = regs->rip;

    return regs->rax;
#else
    (void)regs;
    return (uint64_t)-ENOSYS;
#endif
}

uint64_t sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                             const struct timespec *uts, size_t sigsetsize) {
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }
    if (!uthese) {
        return (uint64_t)-EFAULT;
    }

    sigset_t user_wait_set = 0;
    if (copy_from_user(&user_wait_set, uthese, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }
    sigset_t wait_set = sigset_user_to_kernel(user_wait_set);

    uint64_t deadline = UINT64_MAX;
    if (uts) {
        struct timespec ts;
        if (copy_from_user(&ts, uts, sizeof(ts))) {
            return (uint64_t)-EFAULT;
        }
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L) {
            return (uint64_t)-EINVAL;
        }
        uint64_t wait_ns =
            (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        deadline = nano_time() + wait_ns;
    }

    while (true) {
        siginfo_t info;
        int sig = 0;
        bool interrupted = false;

        spin_lock(&current_task->signal->signal_lock);
        sig = signal_pick_from_set_locked(current_task, wait_set);
        if (sig) {
            signal_take_pending_locked(current_task, sig, &info);
        } else {
            interrupted = signal_has_deliverable_outside_set_locked(
                current_task, wait_set);
        }
        spin_unlock(&current_task->signal->signal_lock);

        if (sig) {
            if (uinfo && copy_to_user(uinfo, &info, sizeof(info))) {
                return (uint64_t)-EFAULT;
            }
            return (uint64_t)sig;
        }

        if (interrupted) {
            return (uint64_t)-EINTR;
        }

        if (deadline != UINT64_MAX && nano_time() >= deadline) {
            return (uint64_t)-EAGAIN;
        }

        schedule(SCHED_FLAG_YIELD);
    }
}

uint64_t sys_rt_sigqueueinfo(uint64_t tgid, uint64_t sig, siginfo_t *info) {
    if (!signal_sig_in_range((int)sig)) {
        return (uint64_t)-EINVAL;
    }
    if (tgid == 0 || tgid >= MAX_TASK_NUM) {
        return (uint64_t)-ESRCH;
    }
    if (!info) {
        return (uint64_t)-EFAULT;
    }

    task_t *task = tasks[tgid];
    if (!task) {
        return (uint64_t)-ESRCH;
    }

    siginfo_t kinfo;
    if (copy_from_user(&kinfo, info, sizeof(kinfo))) {
        return (uint64_t)-EFAULT;
    }

    kinfo.si_signo = (int)sig;
    task_commit_signal(task, (int)sig, &kinfo);

    return 0;
}

uint64_t sys_sigsuspend(const sigset_t *mask, size_t sigsetsize) {
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }
    if (!mask) {
        return (uint64_t)-EFAULT;
    }

    sigset_t user_mask = 0;
    if (copy_from_user(&user_mask, mask, sigsetsize)) {
        return (uint64_t)-EFAULT;
    }

    sigset_t old_mask;
    spin_lock(&current_task->signal->signal_lock);
    old_mask = current_task->signal->blocked;
    current_task->signal->blocked = sigset_user_to_kernel(user_mask);
    spin_unlock(&current_task->signal->signal_lock);

    while (true) {
        bool should_return = false;
        spin_lock(&current_task->signal->signal_lock);
        should_return =
            signal_has_deliverable_outside_set_locked(current_task, 0);
        if (should_return) {
            current_task->signal->blocked = old_mask;
        }
        spin_unlock(&current_task->signal->signal_lock);

        if (should_return) {
            return (uint64_t)-EINTR;
        }

        schedule(SCHED_FLAG_YIELD);
    }
}

void task_fill_siginfo(siginfo_t *info, int sig, int code) {
    signal_fill_kernel_siginfo(info, sig, code);
    info->_sifields._kill._pid = current_task ? current_task->pid : 0;
    info->_sifields._kill._uid = current_task ? current_task->uid : 0;
}

static void signal_notify_signalfd(task_t *task, int sig, int code) {
    if (!task || !task->fd_info) {
        return;
    }

    for (int i = 0; i < MAX_FD_NUM; i++) {
        fd_t *fd = task->fd_info->fds[i];
        if (!fd || !fd->node || fd->node->fsid != signalfdfs_id) {
            continue;
        }

        struct signalfd_ctx *ctx = fd->node->handle;
        if (!ctx || !ctx->queue || ctx->queue_size == 0) {
            continue;
        }

        sigset_t signalfd_mask = sigset_user_to_kernel(ctx->sigmask);
        if (signal_sig_maskable(sig) && !(signalfd_mask & signal_sigbit(sig))) {
            continue;
        }

        struct signalfd_siginfo sinfo;
        memset(&sinfo, 0, sizeof(sinfo));
        sinfo.ssi_signo = sig;
        sinfo.ssi_errno = 0;
        sinfo.ssi_code = code;
        sinfo.ssi_pid = current_task ? current_task->pid : 0;
        sinfo.ssi_uid = current_task ? current_task->uid : 0;

        memcpy(&ctx->queue[ctx->queue_head], &sinfo, sizeof(sinfo));
        ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_size;
        if (ctx->queue_head == ctx->queue_tail) {
            ctx->queue_tail = (ctx->queue_tail + 1) % ctx->queue_size;
        }
    }
}

void task_send_signal(task_t *task, int sig, int code) {
    if (!task || !signal_sig_in_range(sig)) {
        return;
    }

    siginfo_t info;
    task_fill_siginfo(&info, sig, code);
    task_commit_signal(task, sig, &info);
    signal_notify_signalfd(task, sig, code);

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
    if (sig < 0 || sig >= MAXSIG) {
        return (uint64_t)-EINVAL;
    }

    if (pid > 0) {
        if ((uint64_t)pid >= MAX_TASK_NUM || !tasks[pid]) {
            return (uint64_t)-ESRCH;
        }
        if (sig == 0) {
            return 0;
        }
        task_send_signal(tasks[pid], sig, SI_USER);
        return 0;
    }

    int sent = 0;
    if (pid == 0 || pid < -1) {
        int pgid = (pid == 0) ? current_task->pgid : -pid;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            task_t *task = tasks[i];
            if (!task || task->is_kernel || task->pgid != pgid) {
                continue;
            }
            sent++;
            if (sig != 0) {
                task_send_signal(task, sig, SI_USER);
            }
        }
        return sent ? 0 : (uint64_t)-ESRCH;
    }

    if (pid == -1) {
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            task_t *task = tasks[i];
            if (!task || task->is_kernel) {
                continue;
            }
            sent++;
            if (sig != 0) {
                task_send_signal(task, sig, SI_USER);
            }
        }
        return sent ? 0 : (uint64_t)-ESRCH;
    }

    return (uint64_t)-EINVAL;
}

uint64_t sys_tgkill(int tgid, int pid, int sig) {
    if (tgid <= 0 || pid <= 0 || sig < 0 || sig >= MAXSIG) {
        return (uint64_t)-EINVAL;
    }
    if ((uint64_t)pid >= MAX_TASK_NUM) {
        return (uint64_t)-ESRCH;
    }

    task_t *task = tasks[pid];
    if (!task) {
        return (uint64_t)-ESRCH;
    }
    if (task_effective_tgid(task) != tgid) {
        return (uint64_t)-ESRCH;
    }
    if (sig == 0) {
        return 0;
    }

    task_send_signal(task, sig, SI_TKILL);
    return 0;
}

void task_signal(struct pt_regs *regs) {
    task_t *self = current_task;
    if (!self || !self->signal || self->is_kernel || self->arch_context->dead ||
        self->state == TASK_DIED || self->state == TASK_UNINTERRUPTABLE) {
        return;
    }
    if (!signal_arch_user_context(regs)) {
        return;
    }
    if (!self->signal->pending_signal.sig && self->signal->signal == 0) {
        return;
    }

    spin_lock(&self->signal->signal_lock);

    while (true) {
        int sig = signal_pick_deliverable_locked(self);
        if (!sig) {
            spin_unlock(&self->signal->signal_lock);
            return;
        }

        siginfo_t info;
        signal_take_pending_locked(self, sig, &info);

        sigaction_t action = self->signal->actions[sig];

        if (signal_action_ignored(sig, &action)) {
            continue;
        }

        if (action.sa_handler == SIG_DFL) {
            switch (signal_internal_decisions[sig]) {
            case SIGNAL_INTERNAL_TERM:
            case SIGNAL_INTERNAL_CORE:
                spin_unlock(&self->signal->signal_lock);
                task_exit(128 + sig);
                return;
            case SIGNAL_INTERNAL_STOP:
                // self->state = TASK_BLOCKING;
                self->status = 128 + sig;
                spin_unlock(&self->signal->signal_lock);
                return;
            case SIGNAL_INTERNAL_CONT:
                self->state = TASK_READY;
                spin_unlock(&self->signal->signal_lock);
                return;
            case SIGNAL_INTERNAL_IGN:
            default:
                continue;
            }
        }

#if defined(__x86_64__)
        if (!signal_x64_setup_frame(self, regs, sig, &action, &info)) {
            spin_unlock(&self->signal->signal_lock);
            task_exit(128 + SIGSEGV);
            return;
        }
#else
        spin_unlock(&self->signal->signal_lock);
        task_exit(128 + SIGSYS);
        return;
#endif

        if (action.sa_flags & SA_RESETHAND) {
            self->signal->actions[sig].sa_handler = SIG_DFL;
        }

        self->signal->blocked |= action.sa_mask;
        if (!(action.sa_flags & SA_NODEFER) && signal_sig_maskable(sig)) {
            self->signal->blocked |= signal_sigbit(sig);
        }

        uint64_t tmp = self->syscall_stack;
        self->syscall_stack = self->signal_syscall_stack;
        self->signal_syscall_stack = tmp;

        spin_unlock(&self->signal->signal_lock);
        return;
    }
}
