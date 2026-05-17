#pragma once

#include <libs/klibc.h>

typedef struct signal_riscv64_user_sigset {
    uint64_t sig[1];
} signal_riscv64_user_sigset_t;

typedef struct signal_riscv64_user_regs {
    uint64_t pc;
    uint64_t ra;
    uint64_t sp;
    uint64_t gp;
    uint64_t tp;
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t s0;
    uint64_t s1;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    uint64_t a6;
    uint64_t a7;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
    uint64_t s5;
    uint64_t s6;
    uint64_t s7;
    uint64_t s8;
    uint64_t s9;
    uint64_t s10;
    uint64_t s11;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
} signal_riscv64_user_regs_t;

typedef struct signal_riscv64_ctx_header {
    uint32_t magic;
    uint32_t size;
} signal_riscv64_ctx_header_t;

typedef struct signal_riscv64_f_ext_state {
    uint32_t f[32];
    uint32_t fcsr;
} signal_riscv64_f_ext_state_t;

typedef struct signal_riscv64_d_ext_state {
    uint64_t f[32];
    uint32_t fcsr;
} signal_riscv64_d_ext_state_t;

typedef struct signal_riscv64_extra_ext_header {
    uint32_t __padding[129] __attribute__((aligned(16)));
    uint32_t reserved;
    signal_riscv64_ctx_header_t hdr;
} signal_riscv64_extra_ext_header_t;

typedef union signal_riscv64_fp_state {
    signal_riscv64_f_ext_state_t f;
    signal_riscv64_d_ext_state_t d;
    signal_riscv64_extra_ext_header_t q;
} signal_riscv64_fp_state_t;

typedef struct signal_riscv64_sigcontext {
    signal_riscv64_user_regs_t sc_regs;
    union {
        signal_riscv64_fp_state_t sc_fpregs;
        signal_riscv64_extra_ext_header_t sc_extdesc;
    };
} signal_riscv64_sigcontext_t;

typedef struct signal_riscv64_ucontext {
    uint64_t uc_flags;
    struct signal_riscv64_ucontext *uc_link;
    stack_t uc_stack;
    signal_riscv64_user_sigset_t uc_sigmask;
    uint8_t __unused[1024 / 8 - sizeof(signal_riscv64_user_sigset_t)];
    signal_riscv64_sigcontext_t uc_mcontext;
} signal_riscv64_ucontext_t;

typedef struct signal_riscv64_frame {
    siginfo_t info;
    signal_riscv64_ucontext_t ucontext;
    uint64_t flags;
    uint64_t syscall_pc;
} signal_riscv64_frame_t;

_Static_assert(sizeof(signal_riscv64_user_sigset_t) +
                       sizeof(((signal_riscv64_ucontext_t *)0)->__unused) ==
                   1024 / 8,
               "RISC-V user sigset in ucontext must be 1024 bits");
_Static_assert(offsetof(signal_riscv64_ucontext_t, uc_mcontext) == 176,
               "RISC-V ucontext.uc_mcontext offset must match the Linux ABI");
_Static_assert(offsetof(signal_riscv64_sigcontext_t, sc_regs.pc) == 0,
               "RISC-V mcontext PC must be gregs[0] for musl MC_PC");

static inline uint64_t signal_riscv64_align_down(uint64_t value,
                                                 uint64_t align) {
    return value & ~(align - 1);
}

static inline bool
signal_riscv64_prepare_syscall_result(struct pt_regs *saved,
                                      const sigaction_t *action) {
    if (!saved || !action || saved->syscallno == NO_SYSCALL ||
        saved->syscallno == SYS_RT_SIGRETURN)
        return false;

    int64_t retval = (int64_t)saved->a0;
    if (retval < 0) {
        switch (-retval) {
        case ERESTARTNOHAND:
        case ERESTART_RESTARTBLOCK:
        case ERESTARTSYS:
        case ERESTARTNOINTR:
            saved->a0 = (uint64_t)-EINTR;
            break;
        default:
            break;
        }
    }

    return true;
}

static inline void
signal_riscv64_fill_ucontext(signal_riscv64_ucontext_t *ucontext,
                             const struct pt_regs *regs, sigset_t blocked_mask,
                             const stack_t *altstack,
                             const fpu_context_t *fpu_ctx) {
    memset(ucontext, 0, sizeof(*ucontext));

    if (altstack)
        ucontext->uc_stack = *altstack;
    ucontext->uc_sigmask.sig[0] = sigset_kernel_to_user(blocked_mask);

    ucontext->uc_mcontext.sc_regs.pc = regs->sepc;
    ucontext->uc_mcontext.sc_regs.ra = regs->ra;
    ucontext->uc_mcontext.sc_regs.sp = regs->sp;
    ucontext->uc_mcontext.sc_regs.gp = regs->gp;
    ucontext->uc_mcontext.sc_regs.tp = regs->tp;
    ucontext->uc_mcontext.sc_regs.t0 = regs->t0;
    ucontext->uc_mcontext.sc_regs.t1 = regs->t1;
    ucontext->uc_mcontext.sc_regs.t2 = regs->t2;
    ucontext->uc_mcontext.sc_regs.s0 = regs->s0;
    ucontext->uc_mcontext.sc_regs.s1 = regs->s1;
    ucontext->uc_mcontext.sc_regs.a0 = regs->a0;
    ucontext->uc_mcontext.sc_regs.a1 = regs->a1;
    ucontext->uc_mcontext.sc_regs.a2 = regs->a2;
    ucontext->uc_mcontext.sc_regs.a3 = regs->a3;
    ucontext->uc_mcontext.sc_regs.a4 = regs->a4;
    ucontext->uc_mcontext.sc_regs.a5 = regs->a5;
    ucontext->uc_mcontext.sc_regs.a6 = regs->a6;
    ucontext->uc_mcontext.sc_regs.a7 = regs->a7;
    ucontext->uc_mcontext.sc_regs.s2 = regs->s2;
    ucontext->uc_mcontext.sc_regs.s3 = regs->s3;
    ucontext->uc_mcontext.sc_regs.s4 = regs->s4;
    ucontext->uc_mcontext.sc_regs.s5 = regs->s5;
    ucontext->uc_mcontext.sc_regs.s6 = regs->s6;
    ucontext->uc_mcontext.sc_regs.s7 = regs->s7;
    ucontext->uc_mcontext.sc_regs.s8 = regs->s8;
    ucontext->uc_mcontext.sc_regs.s9 = regs->s9;
    ucontext->uc_mcontext.sc_regs.s10 = regs->s10;
    ucontext->uc_mcontext.sc_regs.s11 = regs->s11;
    ucontext->uc_mcontext.sc_regs.t3 = regs->t3;
    ucontext->uc_mcontext.sc_regs.t4 = regs->t4;
    ucontext->uc_mcontext.sc_regs.t5 = regs->t5;
    ucontext->uc_mcontext.sc_regs.t6 = regs->t6;

    memset(&ucontext->uc_mcontext.sc_fpregs, 0,
           sizeof(ucontext->uc_mcontext.sc_fpregs));
    if (fpu_ctx) {
        memcpy(ucontext->uc_mcontext.sc_fpregs.d.f, fpu_ctx->f,
               sizeof(fpu_ctx->f));
        ucontext->uc_mcontext.sc_fpregs.d.fcsr = fpu_ctx->fcsr;
    }
}

static inline void
signal_riscv64_restore_ptregs(struct pt_regs *regs,
                              const signal_riscv64_ucontext_t *ucontext) {
    regs->ra = ucontext->uc_mcontext.sc_regs.ra;
    regs->sp = ucontext->uc_mcontext.sc_regs.sp;
    regs->gp = ucontext->uc_mcontext.sc_regs.gp;
    regs->tp = ucontext->uc_mcontext.sc_regs.tp;
    regs->t0 = ucontext->uc_mcontext.sc_regs.t0;
    regs->t1 = ucontext->uc_mcontext.sc_regs.t1;
    regs->t2 = ucontext->uc_mcontext.sc_regs.t2;
    regs->s0 = ucontext->uc_mcontext.sc_regs.s0;
    regs->s1 = ucontext->uc_mcontext.sc_regs.s1;
    regs->a0 = ucontext->uc_mcontext.sc_regs.a0;
    regs->a1 = ucontext->uc_mcontext.sc_regs.a1;
    regs->a2 = ucontext->uc_mcontext.sc_regs.a2;
    regs->a3 = ucontext->uc_mcontext.sc_regs.a3;
    regs->a4 = ucontext->uc_mcontext.sc_regs.a4;
    regs->a5 = ucontext->uc_mcontext.sc_regs.a5;
    regs->a6 = ucontext->uc_mcontext.sc_regs.a6;
    regs->a7 = ucontext->uc_mcontext.sc_regs.a7;
    regs->s2 = ucontext->uc_mcontext.sc_regs.s2;
    regs->s3 = ucontext->uc_mcontext.sc_regs.s3;
    regs->s4 = ucontext->uc_mcontext.sc_regs.s4;
    regs->s5 = ucontext->uc_mcontext.sc_regs.s5;
    regs->s6 = ucontext->uc_mcontext.sc_regs.s6;
    regs->s7 = ucontext->uc_mcontext.sc_regs.s7;
    regs->s8 = ucontext->uc_mcontext.sc_regs.s8;
    regs->s9 = ucontext->uc_mcontext.sc_regs.s9;
    regs->s10 = ucontext->uc_mcontext.sc_regs.s10;
    regs->s11 = ucontext->uc_mcontext.sc_regs.s11;
    regs->t3 = ucontext->uc_mcontext.sc_regs.t3;
    regs->t4 = ucontext->uc_mcontext.sc_regs.t4;
    regs->t5 = ucontext->uc_mcontext.sc_regs.t5;
    regs->t6 = ucontext->uc_mcontext.sc_regs.t6;
    regs->sepc = ucontext->uc_mcontext.sc_regs.pc;
    regs->sstatus = SIGNAL_RISCV64_USER_SSTATUS;
    regs->syscallno = NO_SYSCALL;
}

static bool signal_riscv64_setup_frame(task_t *task, struct pt_regs *regs,
                                       int sig, const sigaction_t *action,
                                       const siginfo_t *info,
                                       sigset_t restore_mask) {
    struct pt_regs saved = *regs;
    bool from_syscall = signal_riscv64_prepare_syscall_result(&saved, action);

    stack_t frame_altstack;
    signal_altstack_format_old(&frame_altstack, &task->signal->altstack,
                               saved.sp);

    uint64_t stack_top = saved.sp;
    uint64_t trampoline_bytes = 0;
    bool use_kernel_restorer =
        !(action->sa_flags & SA_RESTORER) || !action->sa_restorer;
    if (use_kernel_restorer && !signal_ensure_user_trampoline(task))
        return false;
    bool use_altstack =
        (action->sa_flags & SA_ONSTACK) &&
        signal_altstack_config_enabled(&task->signal->altstack) &&
        !signal_altstack_contains_sp(&task->signal->altstack, saved.sp);
    if (use_altstack) {
        stack_top = signal_stack_base(&task->signal->altstack) +
                    task->signal->altstack.ss_size;
        if (task->signal->altstack.ss_flags & SS_AUTODISARM)
            signal_altstack_disable(&task->signal->altstack);
    }

    if (stack_top <= sizeof(signal_riscv64_frame_t) + trampoline_bytes)
        return false;

    uint64_t frame_addr = signal_riscv64_align_down(
        stack_top - sizeof(signal_riscv64_frame_t), 16);
    if (!frame_addr || frame_addr >= stack_top)
        return false;

    signal_riscv64_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(&frame.info, info, sizeof(frame.info));
    if (from_syscall) {
        frame.flags |= SIGNAL_RISCV64_FRAME_FROM_SYSCALL;
        frame.syscall_pc = saved.sepc;
    }
    riscv64_fpu_save(task->arch_context->fpu_ctx);
    signal_riscv64_fill_ucontext(&frame.ucontext, &saved, restore_mask,
                                 &frame_altstack, task->arch_context->fpu_ctx);

    if (copy_to_user((void *)frame_addr, &frame, sizeof(frame))) {
        return false;
    }

    *regs = saved;
    regs->sepc = (uint64_t)action->sa_handler;
    regs->ra = use_kernel_restorer ? task_mm_signal_trampoline_start(task->mm)
                                   : (uint64_t)action->sa_restorer;
    regs->sp = frame_addr;
    regs->a0 = sig;
    regs->a1 = 0;
    regs->a2 = 0;
    if (action->sa_flags & SA_SIGINFO) {
        regs->a1 = frame_addr + offsetof(signal_riscv64_frame_t, info);
        regs->a2 = frame_addr + offsetof(signal_riscv64_frame_t, ucontext);
    }
    regs->sstatus = (saved.sstatus & ~(1ULL << 8)) | (1ULL << 5);
    regs->syscallno = NO_SYSCALL;

    return true;
}

static bool signal_arch_setup_frame(task_t *task, struct pt_regs *regs, int sig,
                                    const sigaction_t *action,
                                    const siginfo_t *info,
                                    sigset_t restore_mask) {
    return signal_riscv64_setup_frame(task, regs, sig, action, info,
                                      restore_mask);
}

static uint64_t signal_arch_sigreturn(struct pt_regs *regs) {
    arch_disable_interrupt();

    task_t *self = current_task;
    if (!self || !regs) {
        return (uint64_t)-EFAULT;
    }

    if ((regs->sp & 0xFUL) != 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_riscv64_frame_t frame;
    if (copy_from_user(&frame, (void *)regs->sp, sizeof(frame))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    stack_t restore_altstack = frame.ucontext.uc_stack;
    restore_altstack.ss_flags &= ~SS_ONSTACK;
    if (signal_altstack_validate_new(&restore_altstack) < 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_riscv64_restore_ptregs(regs, &frame.ucontext);
    if ((frame.flags & SIGNAL_RISCV64_FRAME_FROM_SYSCALL) != 0 &&
        regs->sepc == frame.syscall_pc) {
        regs->sepc += SIGNAL_RISCV64_SYSCALL_INS_LEN;
    }
    memcpy(self->arch_context->fpu_ctx->f,
           frame.ucontext.uc_mcontext.sc_fpregs.d.f,
           sizeof(self->arch_context->fpu_ctx->f));
    self->arch_context->fpu_ctx->fcsr =
        frame.ucontext.uc_mcontext.sc_fpregs.d.fcsr;
    self->arch_context->fpu_ctx->reserved = 0;
    riscv64_fpu_restore(self->arch_context->fpu_ctx);

    spin_lock(&self->signal->sighand->siglock);
    self->signal->blocked =
        sigset_user_to_kernel(frame.ucontext.uc_sigmask.sig[0]);
    signal_altstack_store(&self->signal->altstack, &restore_altstack);
    spin_unlock(&self->signal->sighand->siglock);

    return regs->a0;
}
