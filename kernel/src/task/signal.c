#include <arch/arch.h>
#include <task/signal.h>

#include <fs/vfs/vfs.h>
#include <task/task.h>

#include <init/abis.h>

#if defined(__x86_64__)
#include <arch/x64/syscall/nr.h>
#endif

#define SIGNAL_MIN_SIGSET_SIZE sizeof(uint32_t)
#define SIGNAL_MAX_SIGSET_SIZE sizeof(sigset_t)
#define SIGNAL_MAX_MASKED_SIG ((int)(sizeof(sigset_t) * 8 - 1))

#if defined(__x86_64__)
#define SIGNAL_X64_SYSCALL_INS_LEN 2
#define SIGNAL_X64_MAX_SYSCALL_NR 1024
#define SIGNAL_X64_UC_SIGCONTEXT_SS 0x2
#define SIGNAL_X64_UC_STRICT_RESTORE_SS 0x4
#define SIGNAL_X64_TRAPNO_PAGE_FAULT 14

#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

typedef struct signal_x64_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    void (*restorer)(void);
    sigset_t mask;
} signal_x64_kernel_sigaction_t;
#endif

signal_internal_t signal_internal_decisions[MAXSIG] = {0};

extern int signalfdfs_id;

bool signal_sig_in_range(int sig) { return sig >= MINSIG && sig < MAXSIG; }

bool signal_sig_maskable(int sig) {
    return sig >= MINSIG && sig <= SIGNAL_MAX_MASKED_SIG;
}

bool signal_sigset_size_valid(size_t sigsetsize) {
    return sigsetsize >= SIGNAL_MIN_SIGSET_SIZE &&
           sigsetsize <= SIGNAL_MAX_SIGSET_SIZE;
}

sigset_t signal_sigbit(int sig) { return (sigset_t)1ULL << (uint64_t)sig; }

sigset_t sigset_user_to_kernel(sigset_t user_mask) {
    sigset_t k = user_mask << 1;
    if (signal_sig_maskable(SIGKILL)) {
        k &= ~signal_sigbit(SIGKILL);
    }
    if (signal_sig_maskable(SIGSTOP)) {
        k &= ~signal_sigbit(SIGSTOP);
    }
    return k;
}

sigset_t sigset_kernel_to_user(sigset_t kernel_mask) {
    return kernel_mask >> 1;
}

bool signal_sigset_has(sigset_t set, int sig) {
    if (!signal_sig_maskable(sig)) {
        return false;
    }
    return (set & signal_sigbit(sig)) != 0;
}

void signal_altstack_disable(stack_t *stack) {
    if (!stack)
        return;

    stack->ss_sp = NULL;
    stack->ss_size = 0;
    stack->ss_flags = SS_DISABLE;
}

uint64_t signal_stack_base(const stack_t *stack) {
    return stack ? (uint64_t)stack->ss_sp : 0;
}

bool signal_altstack_config_enabled(const stack_t *stack) {
    return stack && (stack->ss_flags & SS_DISABLE) == 0 && stack->ss_size > 0;
}

bool signal_altstack_contains_sp(const stack_t *stack, uint64_t sp) {
    if (!signal_altstack_config_enabled(stack))
        return false;

    uint64_t base = signal_stack_base(stack);
    if (base > UINT64_MAX - stack->ss_size)
        return false;

    uint64_t end = base + stack->ss_size;
    return sp >= base && sp < end;
}

int signal_altstack_status_flags(const stack_t *stack, uint64_t sp) {
    if (!stack || (stack->ss_flags & SS_DISABLE) != 0 || stack->ss_size == 0)
        return SS_DISABLE;

    int flags = stack->ss_flags & SS_AUTODISARM;
    if (signal_altstack_contains_sp(stack, sp))
        flags |= SS_ONSTACK;
    return flags;
}

void signal_altstack_format_old(stack_t *dst, const stack_t *src, uint64_t sp) {
    if (!dst)
        return;

    if (!src) {
        signal_altstack_disable(dst);
        return;
    }

    *dst = *src;
    dst->ss_flags = signal_altstack_status_flags(src, sp);
}

int signal_altstack_validate_new(const stack_t *stack) {
    if (!stack)
        return -EINVAL;

    if (stack->ss_flags & SS_DISABLE)
        return 0;

    int allowed_flags = SS_ONSTACK | SS_AUTODISARM;
    if (stack->ss_flags & ~allowed_flags)
        return -EINVAL;

    if (stack->ss_size < MINSIGSTKSZ)
        return -ENOMEM;

    return 0;
}

void signal_altstack_store(stack_t *dst, const stack_t *src) {
    if (!dst || !src)
        return;

    if (src->ss_flags & SS_DISABLE) {
        signal_altstack_disable(dst);
        return;
    }

    *dst = *src;
    dst->ss_flags &= ~SS_ONSTACK;
    dst->ss_flags &= SS_AUTODISARM;
}

static inline uint64_t signal_current_user_sp(task_t *task) {
    if (!task)
        return 0;

#if defined(__x86_64__)
    struct pt_regs *regs = (struct pt_regs *)task->syscall_stack - 1;
    return regs->rsp;
#elif defined(__aarch64__)
    struct pt_regs *regs = (struct pt_regs *)task->syscall_stack - 1;
    return regs->sp_el0;
#elif defined(__riscv__)
    struct pt_regs *regs = (struct pt_regs *)task->syscall_stack - 1;
    return regs->sp;
#elif defined(__loongarch64)
    struct pt_regs *regs = (struct pt_regs *)task->syscall_stack - 1;
    return regs->usp;
#else
    return 0;
#endif
}

static inline bool signal_is_blocked(sigset_t blocked, int sig) {
    if (sig == SIGKILL || sig == SIGSTOP) {
        return false;
    }
    return signal_sigset_has(blocked, sig);
}

static inline sigset_t signal_pending_mask_locked(task_t *task) {
    return task->signal->signal;
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

static bool signal_should_wake_task_locked(task_t *task, int sig) {
    if (!task || !task->signal || !task->signal->sighand ||
        !signal_sig_in_range(sig)) {
        return false;
    }

    if (signal_is_blocked(task->signal->blocked, sig)) {
        return false;
    }

    sigaction_t *action = &task->signal->sighand->actions[sig];
    return !signal_action_ignored(sig, action);
}

static bool signal_should_wake_task(task_t *task, int sig) {
    if (!task || !task->signal || !task->signal->sighand ||
        !signal_sig_in_range(sig)) {
        return false;
    }

    bool should_wake;
    spin_lock(&task->signal->sighand->siglock);
    should_wake = signal_should_wake_task_locked(task, sig);
    spin_unlock(&task->signal->sighand->siglock);

    return should_wake;
}

static inline void signal_wake_interruptible_task(task_t *task, int sig) {
    if (!task || !signal_sig_in_range(sig))
        return;

    if (task->state != TASK_BLOCKING && task->state != TASK_READING_STDIO)
        return;

    if (!signal_should_wake_task(task, sig))
        return;

    task_unblock(task, 128 + sig);
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

    return 0;
}

static inline void signal_take_pending_locked(task_t *task, int sig,
                                              siginfo_t *info) {
    if (signal_sig_maskable(sig)) {
        sigset_t bit = signal_sigbit(sig);
        task->signal->signal &= ~bit;

        if (task->signal->pending_signal.info_mask & bit) {
            memcpy(info, &task->signal->pending_signal.info[sig],
                   sizeof(*info));
            task->signal->pending_signal.info_mask &= ~bit;
            memset(&task->signal->pending_signal.info[sig], 0,
                   sizeof(task->signal->pending_signal.info[sig]));
            return;
        }
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
        sigaction_t *action = &task->signal->sighand->actions[sig];
        if (signal_action_ignored(sig, action)) {
            continue;
        }
        return true;
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
           regs->rflags == regs->r11 &&
           regs->orig_rax <= SIGNAL_X64_MAX_SYSCALL_NR;
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
        uint64_t nr = saved->orig_rax;
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

typedef struct signal_x64_frame_layout {
    uint64_t frame_rsp;
    uint64_t ucontext_addr;
    uint64_t siginfo_addr;
    uint64_t fpstate_addr;
    uint64_t fpstate_bytes;
} signal_x64_frame_layout_t;

static inline uint64_t signal_x64_align_up(uint64_t value, uint64_t align) {
    return (value + align - 1) & ~(align - 1);
}

static uint64_t signal_x64_saved_fpstate_bytes(void) {
    uint64_t bytes = x64_fpu_state_size();

    if (bytes < sizeof(fpu_context_t))
        bytes = sizeof(fpu_context_t);

    return bytes;
}

static uint64_t signal_x64_user_fpstate_bytes(void) {
    uint64_t bytes = signal_x64_saved_fpstate_bytes();

    if (x64_fpu_xsave_enabled())
        bytes += X64_FP_XSTATE_MAGIC2_SIZE;

    return bytes;
}

static void signal_x64_build_frame_layout(uint64_t user_rsp,
                                          uint64_t fpstate_bytes,
                                          signal_x64_frame_layout_t *layout) {
    if (!layout)
        return;

    memset(layout, 0, sizeof(*layout));

    uint64_t redzone_top = user_rsp - 128;
    uint64_t fixed_bytes =
        sizeof(void *) + sizeof(ucontext_t) + sizeof(siginfo_t);
    uint64_t reserve = fixed_bytes + (X64_FPU_FRAME_ALIGN - 1) + fpstate_bytes;

    if (redzone_top <= reserve)
        return;

    uint64_t frame_rsp = redzone_top - reserve;
    frame_rsp =
        (frame_rsp & ~(uint64_t)(X64_FPU_FRAME_ALIGN - 1)) + sizeof(void *);
    if (frame_rsp > redzone_top - reserve)
        frame_rsp -= X64_FPU_FRAME_ALIGN;

    layout->frame_rsp = frame_rsp;
    layout->ucontext_addr = frame_rsp + sizeof(void *);
    layout->siginfo_addr = layout->ucontext_addr + sizeof(ucontext_t);
    layout->fpstate_addr = signal_x64_align_up(
        layout->siginfo_addr + sizeof(siginfo_t), X64_FPU_FRAME_ALIGN);
    layout->fpstate_bytes = fpstate_bytes;
}

static bool signal_x64_copy_fpstate_to_user(task_t *task,
                                            uint64_t user_fpstate_addr,
                                            uint64_t fpstate_bytes) {
    if (!task || !task->arch_context || !task->arch_context->fpu_ctx)
        return false;

    uint64_t saved_bytes = signal_x64_saved_fpstate_bytes();
    void *image = alloc_frames_bytes(fpstate_bytes);
    uint64_t image_phys = image ? virt_to_phys((uint64_t)image) : 0;

    if (!image_phys)
        return false;

    memset(image, 0, fpstate_bytes);
    memcpy(image, task->arch_context->fpu_ctx, saved_bytes);

    fpu_context_t *fp = (fpu_context_t *)image;
    if (x64_fpu_xsave_enabled()) {
        uint64_t xfeatures = X64_XSTATE_X87 | X64_XSTATE_SSE;
        if (saved_bytes > X64_XSAVE_HDR_OFFSET) {
            const x64_xsave_header_t *hdr =
                (const x64_xsave_header_t *)((const uint8_t *)image +
                                             X64_XSAVE_HDR_OFFSET);
            if (hdr->xstate_bv)
                xfeatures = hdr->xstate_bv;
        }

        fp->sw_reserved.magic1 = X64_FP_XSTATE_MAGIC1;
        fp->sw_reserved.extended_size = (uint32_t)fpstate_bytes;
        fp->sw_reserved.xstate_bv = xfeatures;
        fp->sw_reserved.xstate_size = (uint32_t)saved_bytes;
        *(uint32_t *)((uint8_t *)image + fpstate_bytes -
                      X64_FP_XSTATE_MAGIC2_SIZE) = X64_FP_XSTATE_MAGIC2;
    } else {
        memset(&fp->sw_reserved, 0, sizeof(fp->sw_reserved));
    }

    bool ok = !copy_to_user((void *)user_fpstate_addr, image, fpstate_bytes);
    free_frames_bytes(image, fpstate_bytes);
    return ok;
}

static uint64_t signal_x64_restore_fpstate_bytes(const ucontext_t *ucontext) {
    if (!ucontext)
        return sizeof(fpu_context_t);

    if ((ucontext->uc_flags & X64_UC_FP_XSTATE) && x64_fpu_xsave_enabled())
        return signal_x64_saved_fpstate_bytes();

    return sizeof(fpu_context_t);
}

static inline void signal_x64_fill_ucontext(ucontext_t *ucontext,
                                            const struct pt_regs *regs,
                                            sigset_t blocked_mask,
                                            const stack_t *altstack,
                                            const fpu_context_t *fpu_ctx) {
    memset(ucontext, 0, sizeof(*ucontext));

    ucontext->uc_flags =
        SIGNAL_X64_UC_SIGCONTEXT_SS | SIGNAL_X64_UC_STRICT_RESTORE_SS;
    if (x64_fpu_xsave_enabled())
        ucontext->uc_flags |= X64_UC_FP_XSTATE;
    ucontext->uc_link = NULL;
    if (altstack)
        ucontext->uc_stack = *altstack;
    if (fpu_ctx) {
        memcpy(&ucontext->__fpregs_mem, fpu_ctx,
               sizeof(ucontext->__fpregs_mem));
    }
    ucontext->uc_mcontext.fpregs = NULL;

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
        (regs->cs & 0xFFFFULL) | ((uint64_t)0 << 16) | ((uint64_t)0 << 32) |
        ((regs->ss & 0xFFFFULL) << 48);
    ucontext->uc_mcontext.gregs[X64_REG_ERR] = regs->errcode;
    ucontext->uc_mcontext.gregs[X64_REG_TRAPNO] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_OLDMASK] = 0;
    ucontext->uc_mcontext.gregs[X64_REG_CR2] = 0;
    memset(&ucontext->uc_sigmask, 0, sizeof(ucontext->uc_sigmask));
    ucontext->uc_sigmask.__bits[0] = sigset_kernel_to_user(blocked_mask);
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

    stack_t frame_altstack;
    signal_altstack_format_old(&frame_altstack, &task->signal->altstack,
                               saved.rsp);

    uint64_t fpstate_bytes = signal_x64_user_fpstate_bytes();
    signal_x64_frame_layout_t layout;
    signal_x64_build_frame_layout(saved.rsp, fpstate_bytes, &layout);
    bool use_altstack =
        (action->sa_flags & SA_ONSTACK) &&
        signal_altstack_config_enabled(&task->signal->altstack) &&
        !signal_altstack_contains_sp(&task->signal->altstack, saved.rsp);
    if (use_altstack) {
        uint64_t alt_top = signal_stack_base(&task->signal->altstack) +
                           task->signal->altstack.ss_size;
        signal_x64_build_frame_layout(alt_top, fpstate_bytes, &layout);
        if (task->signal->altstack.ss_flags & SS_AUTODISARM)
            signal_altstack_disable(&task->signal->altstack);
    }
    if (!layout.frame_rsp)
        return false;

    uint64_t ucontext_addr = layout.ucontext_addr;
    uint64_t siginfo_addr = layout.siginfo_addr;

    ucontext_t frame_ucontext;
    x64_fpu_save(task->arch_context->fpu_ctx);
    signal_x64_fill_ucontext(&frame_ucontext, &saved, task->signal->blocked,
                             &frame_altstack, task->arch_context->fpu_ctx);
    if (sig == SIGSEGV && info) {
        frame_ucontext.uc_mcontext.gregs[X64_REG_TRAPNO] =
            SIGNAL_X64_TRAPNO_PAGE_FAULT;
        frame_ucontext.uc_mcontext.gregs[X64_REG_CR2] =
            (uint64_t)info->_sifields._sigfault._addr;
    }
    frame_ucontext.uc_mcontext.fpregs = (fpu_context_t *)layout.fpstate_addr;

    void *frame_restorer = (void *)action->sa_restorer;
    if (!signal_x64_copy_fpstate_to_user(task, layout.fpstate_addr,
                                         layout.fpstate_bytes)) {
        return false;
    }

    if (copy_to_user((void *)siginfo_addr, info, sizeof(*info)) ||
        copy_to_user((void *)ucontext_addr, &frame_ucontext,
                     sizeof(frame_ucontext)) ||
        copy_to_user((void *)layout.frame_rsp, &frame_restorer,
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
    regs->rsp = layout.frame_rsp;
    regs->rbp = layout.frame_rsp;

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

    spin_lock(&task->signal->sighand->siglock);

    if (signal_sig_maskable(sig)) {
        sigset_t bit = signal_sigbit(sig);
        if ((task->signal->signal & bit) == 0) {
            memcpy(&task->signal->pending_signal.info[sig], &kinfo,
                   sizeof(kinfo));
            task->signal->pending_signal.info_mask |= bit;
        }
        task->signal->signal |= bit;
    }

    spin_unlock(&task->signal->sighand->siglock);

    system_abi->on_send_signal(task, sig, &kinfo);

    signal_wake_interruptible_task(task, sig);
}

bool task_signal_has_deliverable(task_t *task) {
    if (!task || !task->signal || !task->signal->sighand) {
        return false;
    }

    bool deliverable = false;
    spin_lock(&task->signal->sighand->siglock);
    deliverable = signal_has_deliverable_outside_set_locked(task, 0);
    spin_unlock(&task->signal->sighand->siglock);

    return deliverable;
}

uint64_t sys_ssetmask(int how, const sigset_t *nset, sigset_t *oset,
                      size_t sigsetsize) {
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }

    spin_lock(&current_task->signal->sighand->siglock);

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
            spin_unlock(&current_task->signal->sighand->siglock);
            return (uint64_t)-EINVAL;
        }
    }

    spin_unlock(&current_task->signal->sighand->siglock);
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

uint64_t sys_sigaction(int sig, const void *action, void *oldaction,
                       size_t sigsetsize) {
    if (!signal_sig_in_range(sig) || sig == SIGKILL || sig == SIGSTOP) {
        return (uint64_t)-EINVAL;
    }
    if (!signal_sigset_size_valid(sigsetsize)) {
        return (uint64_t)-EINVAL;
    }

    sigaction_t new_action;
    bool has_new = action != NULL;
    if (has_new) {
        signal_x64_kernel_sigaction_t user_action;
        if (copy_from_user(&user_action, action, sizeof(user_action))) {
            return (uint64_t)-EFAULT;
        }
        memset(&new_action, 0, sizeof(new_action));
        new_action.sa_handler = user_action.handler;
        new_action.sa_flags = (int)user_action.flags;
        new_action.sa_restorer = user_action.restorer;
        new_action.sa_mask = sigset_user_to_kernel(user_action.mask);
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

    spin_lock(&current_task->signal->sighand->siglock);
    sigaction_t *slot = &current_task->signal->sighand->actions[sig];
    if (has_old) {
        old_local = *slot;
    }
    if (has_new) {
        *slot = new_action;
    }
    spin_unlock(&current_task->signal->sighand->siglock);

    if (has_old) {
        signal_x64_kernel_sigaction_t user_old = {
            .handler = old_local.sa_handler,
            .flags = (unsigned long)old_local.sa_flags,
            .restorer = old_local.sa_restorer,
            .mask = sigset_kernel_to_user(old_local.sa_mask),
        };

        if (copy_to_user(oldaction, &user_old, sizeof(user_old))) {
            return (uint64_t)-EFAULT;
        }
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

    if (frame_ucontext.uc_mcontext.fpregs && ({
            x64_fpu_state_init(self->arch_context->fpu_ctx);
            copy_from_user(self->arch_context->fpu_ctx,
                           frame_ucontext.uc_mcontext.fpregs,
                           signal_x64_restore_fpstate_bytes(&frame_ucontext));
        })) {
        task_exit(128 + SIGSEGV);
        return 0;
    }
    x64_fpu_restore(self->arch_context->fpu_ctx);

    stack_t restore_altstack = frame_ucontext.uc_stack;
    restore_altstack.ss_flags &= ~SS_ONSTACK;
    if (signal_altstack_validate_new(&restore_altstack) < 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_x64_restore_ptregs(regs, &frame_ucontext);

    spin_lock(&self->signal->sighand->siglock);
    self->signal->blocked =
        sigset_user_to_kernel(frame_ucontext.uc_sigmask.__bits[0]);
    signal_altstack_store(&self->signal->altstack, &restore_altstack);
    spin_unlock(&self->signal->sighand->siglock);

    regs->rflags |= (1ULL << 9);
    regs->r11 = regs->rflags;
    regs->rcx = regs->rip;

    return regs->rax;
#else
    (void)regs;
    return (uint64_t)-ENOSYS;
#endif
}

uint64_t sys_sigaltstack(const stack_t *uss, stack_t *uoss) {
    task_t *self = current_task;
    if (!self || !self->signal)
        return (uint64_t)-EINVAL;

    stack_t new_stack;
    bool has_new = uss != NULL;
    if (has_new && copy_from_user(&new_stack, uss, sizeof(new_stack)))
        return (uint64_t)-EFAULT;

    uint64_t user_sp = signal_current_user_sp(self);
    stack_t old_stack;

    spin_lock(&self->signal->sighand->siglock);
    signal_altstack_format_old(&old_stack, &self->signal->altstack, user_sp);

    if (has_new) {
        int ret = signal_altstack_validate_new(&new_stack);
        if (ret < 0) {
            spin_unlock(&self->signal->sighand->siglock);
            return (uint64_t)ret;
        }
        if (old_stack.ss_flags & SS_ONSTACK) {
            spin_unlock(&self->signal->sighand->siglock);
            return (uint64_t)-EPERM;
        }
        signal_altstack_store(&self->signal->altstack, &new_stack);
    }

    spin_unlock(&self->signal->sighand->siglock);

    if (uoss && copy_to_user(uoss, &old_stack, sizeof(old_stack)))
        return (uint64_t)-EFAULT;

    return 0;
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

        spin_lock(&current_task->signal->sighand->siglock);
        sig = signal_pick_from_set_locked(current_task, wait_set);
        if (sig) {
            signal_take_pending_locked(current_task, sig, &info);
        } else {
            interrupted = signal_has_deliverable_outside_set_locked(
                current_task, wait_set);
        }
        spin_unlock(&current_task->signal->sighand->siglock);

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
    if (tgid == 0) {
        return (uint64_t)-ESRCH;
    }
    if (!info) {
        return (uint64_t)-EFAULT;
    }

    task_t *task = task_find_by_pid(tgid);
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
    spin_lock(&current_task->signal->sighand->siglock);
    old_mask = current_task->signal->blocked;
    current_task->signal->blocked = sigset_user_to_kernel(user_mask);
    spin_unlock(&current_task->signal->sighand->siglock);

    while (true) {
        bool should_return = false;
        spin_lock(&current_task->signal->sighand->siglock);
        should_return =
            signal_has_deliverable_outside_set_locked(current_task, 0);
        if (should_return) {
            current_task->signal->blocked = old_mask;
        }
        spin_unlock(&current_task->signal->sighand->siglock);

        if (should_return) {
            return (uint64_t)-EINTR;
        }

        schedule(SCHED_FLAG_YIELD);
    }
}

void task_fill_siginfo(siginfo_t *info, int sig, int code) {
    signal_fill_kernel_siginfo(info, sig, code);
    info->_sifields._kill._pid =
        current_task ? (int)task_effective_tgid(current_task) : 0;
    info->_sifields._kill._uid = current_task ? current_task->uid : 0;
}

void task_send_signal(task_t *task, int sig, int code) {
    if (!task || !signal_sig_in_range(sig)) {
        return;
    }

    siginfo_t info;
    task_fill_siginfo(&info, sig, code);
    task_commit_signal(task, sig, &info);
}

uint64_t sys_kill(int pid, int sig) {
    if (sig < 0 || sig >= MAXSIG) {
        return (uint64_t)-EINVAL;
    }

    if (pid > 0) {
        task_t *target = task_find_by_pid((uint64_t)pid);
        if (!target) {
            return (uint64_t)-ESRCH;
        }
        if (sig == 0) {
            return 0;
        }
        task_send_signal(target, sig, SI_USER);
        return 0;
    }

    int sent = 0;
    if (pid == 0 || pid < -1) {
        int pgid = (pid == 0) ? current_task->pgid : -pid;
        sent = task_kill_process_group(pgid, sig);
        return sent ? 0 : (uint64_t)-ESRCH;
    }

    if (pid == -1) {
        sent = task_kill_all(sig);
        return sent ? 0 : (uint64_t)-ESRCH;
    }

    return (uint64_t)-EINVAL;
}

uint64_t sys_tgkill(int tgid, int pid, int sig) {
    if (tgid <= 0 || pid <= 0 || sig < 0 || sig >= MAXSIG) {
        return (uint64_t)-EINVAL;
    }

    task_t *task = task_find_by_pid((uint64_t)pid);
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

__attribute__((used)) void task_signal(struct pt_regs *regs) {
    task_t *self = current_task;
    if (!self || !self->signal || self->is_kernel || self->arch_context->dead ||
        self->state == TASK_DIED || self->state == TASK_UNINTERRUPTABLE) {
        return;
    }
    if (!signal_arch_user_context(regs)) {
        return;
    }
    if (self->signal->signal == 0) {
        return;
    }

    spin_lock(&self->signal->sighand->siglock);

    while (true) {
        int sig = signal_pick_deliverable_locked(self);
        if (!sig) {
            spin_unlock(&self->signal->sighand->siglock);
            return;
        }

        siginfo_t info;
        signal_take_pending_locked(self, sig, &info);

        sigaction_t action = self->signal->sighand->actions[sig];

        if (signal_action_ignored(sig, &action)) {
            continue;
        }

        if (action.sa_handler == SIG_DFL) {
            switch (signal_internal_decisions[sig]) {
            case SIGNAL_INTERNAL_TERM:
            case SIGNAL_INTERNAL_CORE:
                spin_unlock(&self->signal->sighand->siglock);
                task_exit(128 + sig);
                return;
            case SIGNAL_INTERNAL_STOP:
                // self->state = TASK_BLOCKING;
                self->status = 128 + sig;
                spin_unlock(&self->signal->sighand->siglock);
                return;
            case SIGNAL_INTERNAL_CONT:
                self->state = TASK_READY;
                spin_unlock(&self->signal->sighand->siglock);
                return;
            case SIGNAL_INTERNAL_IGN:
            default:
                continue;
            }
        }

#if defined(__x86_64__)
        if (!signal_x64_setup_frame(self, regs, sig, &action, &info)) {
            spin_unlock(&self->signal->sighand->siglock);
            task_exit(128 + SIGSEGV);
            return;
        }
#else
        spin_unlock(&self->signal->sighand->siglock);
        task_exit(128 + SIGSYS);
        return;
#endif

        if (action.sa_flags & SA_RESETHAND) {
            self->signal->sighand->actions[sig].sa_handler = SIG_DFL;
        }

        self->signal->blocked |= action.sa_mask;
        if (!(action.sa_flags & SA_NODEFER) && signal_sig_maskable(sig)) {
            self->signal->blocked |= signal_sigbit(sig);
        }

        spin_unlock(&self->signal->sighand->siglock);
        return;
    }
}
