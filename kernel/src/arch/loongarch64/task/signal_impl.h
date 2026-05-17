#pragma once

#include <libs/klibc.h>

typedef struct signal_loongarch64_user_sigset {
    uint64_t sig[1];
} signal_loongarch64_user_sigset_t;

#define SIGNAL_LOONGARCH64_SC_USED_FP (1U << 0)
#define SIGNAL_LOONGARCH64_FPU_CTX_MAGIC 0x46505501U
#define SIGNAL_LOONGARCH64_LSX_CTX_MAGIC 0x53580001U

typedef struct signal_loongarch64_sctx_info {
    uint32_t magic;
    uint32_t size;
    uint64_t padding;
} signal_loongarch64_sctx_info_t;

typedef struct signal_loongarch64_fpu_context {
    uint64_t regs[32];
    uint64_t fcc;
    uint32_t fcsr;
} signal_loongarch64_fpu_context_t;

typedef struct signal_loongarch64_lsx_context {
    uint64_t regs[2 * 32];
    uint64_t fcc;
    uint32_t fcsr;
} signal_loongarch64_lsx_context_t;

typedef struct signal_loongarch64_sigcontext {
    uint64_t sc_pc;
    uint64_t sc_regs[32];
    uint32_t sc_flags;
    uint64_t sc_extcontext[0] __attribute__((aligned(16)));
} signal_loongarch64_sigcontext_t;

typedef struct signal_loongarch64_ucontext {
    uint64_t uc_flags;
    struct signal_loongarch64_ucontext *uc_link;
    stack_t uc_stack;
    signal_loongarch64_user_sigset_t uc_sigmask;
    uint8_t __unused[1024 / 8 - sizeof(signal_loongarch64_user_sigset_t)];
    signal_loongarch64_sigcontext_t uc_mcontext;
} signal_loongarch64_ucontext_t;

typedef struct signal_loongarch64_lsx_extcontext {
    signal_loongarch64_sctx_info_t header;
    signal_loongarch64_lsx_context_t context;
} __attribute__((aligned(16))) signal_loongarch64_lsx_extcontext_t;

typedef struct signal_loongarch64_fpu_extcontext {
    signal_loongarch64_sctx_info_t header;
    signal_loongarch64_fpu_context_t context;
} __attribute__((aligned(16))) signal_loongarch64_fpu_extcontext_t;

typedef struct signal_loongarch64_extcontext {
    signal_loongarch64_lsx_extcontext_t lsx;
    signal_loongarch64_sctx_info_t end;
} __attribute__((aligned(16))) signal_loongarch64_extcontext_t;

typedef struct signal_loongarch64_frame {
    siginfo_t info;
    signal_loongarch64_ucontext_t ucontext;
    signal_loongarch64_extcontext_t extcontext;
    uint64_t flags;
    uint64_t syscall_pc;
} signal_loongarch64_frame_t;

_Static_assert(sizeof(signal_loongarch64_user_sigset_t) +
                       sizeof(((signal_loongarch64_ucontext_t *)0)->__unused) ==
                   1024 / 8,
               "LoongArch64 user sigset in ucontext must be 1024 bits");
_Static_assert(offsetof(signal_loongarch64_ucontext_t, uc_mcontext) == 176,
               "LoongArch64 ucontext.uc_mcontext offset must match Linux ABI");
_Static_assert(sizeof(signal_loongarch64_sigcontext_t) == 272,
               "LoongArch64 sigcontext size must match Linux ABI");
_Static_assert(sizeof(signal_loongarch64_sctx_info_t) == 16,
               "LoongArch64 sctx_info size must match Linux ABI");

static inline uint64_t signal_loongarch64_align_down(uint64_t value,
                                                     uint64_t align) {
    return value & ~(align - 1);
}

static inline void
signal_loongarch64_save_lsx(signal_loongarch64_extcontext_t *extcontext,
                            const fpu_context_t *fpu_ctx) {
    memset(extcontext, 0, sizeof(*extcontext));
    if (!fpu_ctx)
        return;

    extcontext->lsx.header.magic = SIGNAL_LOONGARCH64_LSX_CTX_MAGIC;
    extcontext->lsx.header.size = sizeof(signal_loongarch64_lsx_extcontext_t);
    memcpy(extcontext->lsx.context.regs, fpu_ctx->v,
           sizeof(extcontext->lsx.context.regs));
    extcontext->lsx.context.fcc = fpu_ctx->fcc;
    extcontext->lsx.context.fcsr = fpu_ctx->fcsr;
}

static inline bool
signal_loongarch64_restore_extcontext(const signal_loongarch64_frame_t *frame,
                                      fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return true;

    loongarch64_fpu_state_init(fpu_ctx);

    const uint8_t *cursor =
        (const uint8_t *)frame->ucontext.uc_mcontext.sc_extcontext;
    const uint8_t *limit = (const uint8_t *)&frame->flags;
    bool fp_seen = false;

    while (cursor + sizeof(signal_loongarch64_sctx_info_t) <= limit) {
        const signal_loongarch64_sctx_info_t *header =
            (const signal_loongarch64_sctx_info_t *)cursor;

        if (header->magic == 0 && header->size == 0)
            return true;

        if ((header->size & 0xFUL) != 0 ||
            header->size < sizeof(signal_loongarch64_sctx_info_t) ||
            cursor + header->size > limit) {
            return false;
        }

        switch (header->magic) {
        case SIGNAL_LOONGARCH64_LSX_CTX_MAGIC: {
            if (fp_seen ||
                header->size != sizeof(signal_loongarch64_lsx_extcontext_t))
                return false;

            const signal_loongarch64_lsx_extcontext_t *lsx =
                (const signal_loongarch64_lsx_extcontext_t *)cursor;
            memcpy(fpu_ctx->v, lsx->context.regs, sizeof(fpu_ctx->v));
            fpu_ctx->fcc = lsx->context.fcc;
            fpu_ctx->fcsr = lsx->context.fcsr;
            fp_seen = true;
            break;
        }
        case SIGNAL_LOONGARCH64_FPU_CTX_MAGIC: {
            if (fp_seen ||
                header->size != sizeof(signal_loongarch64_fpu_extcontext_t))
                return false;

            const signal_loongarch64_fpu_extcontext_t *fpu =
                (const signal_loongarch64_fpu_extcontext_t *)cursor;
            for (size_t i = 0; i < 32; i++)
                fpu_ctx->v[i][0] = fpu->context.regs[i];
            fpu_ctx->fcc = fpu->context.fcc;
            fpu_ctx->fcsr = fpu->context.fcsr;
            fp_seen = true;
            break;
        }
        default:
            break;
        }

        cursor += header->size;
    }

    return false;
}

static inline bool
signal_loongarch64_prepare_syscall_result(struct pt_regs *saved,
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
signal_loongarch64_fill_sigcontext(signal_loongarch64_sigcontext_t *sigcontext,
                                   const struct pt_regs *regs) {
    memset(sigcontext, 0, sizeof(*sigcontext));
    sigcontext->sc_pc = regs->pc;
    sigcontext->sc_flags = SIGNAL_LOONGARCH64_SC_USED_FP;

    sigcontext->sc_regs[0] = 0;
    sigcontext->sc_regs[1] = regs->ra;
    sigcontext->sc_regs[2] = regs->tp;
    sigcontext->sc_regs[3] = regs->sp;
    sigcontext->sc_regs[4] = regs->a0;
    sigcontext->sc_regs[5] = regs->a1;
    sigcontext->sc_regs[6] = regs->a2;
    sigcontext->sc_regs[7] = regs->a3;
    sigcontext->sc_regs[8] = regs->a4;
    sigcontext->sc_regs[9] = regs->a5;
    sigcontext->sc_regs[10] = regs->a6;
    sigcontext->sc_regs[11] = regs->a7;
    sigcontext->sc_regs[12] = regs->t0;
    sigcontext->sc_regs[13] = regs->t1;
    sigcontext->sc_regs[14] = regs->t2;
    sigcontext->sc_regs[15] = regs->t3;
    sigcontext->sc_regs[16] = regs->t4;
    sigcontext->sc_regs[17] = regs->t5;
    sigcontext->sc_regs[18] = regs->t6;
    sigcontext->sc_regs[19] = regs->t7;
    sigcontext->sc_regs[20] = regs->t8;
    sigcontext->sc_regs[21] = regs->r21;
    sigcontext->sc_regs[22] = regs->fp;
    sigcontext->sc_regs[23] = regs->s0;
    sigcontext->sc_regs[24] = regs->s1;
    sigcontext->sc_regs[25] = regs->s2;
    sigcontext->sc_regs[26] = regs->s3;
    sigcontext->sc_regs[27] = regs->s4;
    sigcontext->sc_regs[28] = regs->s5;
    sigcontext->sc_regs[29] = regs->s6;
    sigcontext->sc_regs[30] = regs->s7;
    sigcontext->sc_regs[31] = regs->s8;
}

static inline void signal_loongarch64_fill_ucontext(
    signal_loongarch64_ucontext_t *ucontext, const struct pt_regs *regs,
    sigset_t blocked_mask, const stack_t *altstack) {
    memset(ucontext, 0, sizeof(*ucontext));

    if (altstack)
        ucontext->uc_stack = *altstack;
    ucontext->uc_sigmask.sig[0] = sigset_kernel_to_user(blocked_mask);
    signal_loongarch64_fill_sigcontext(&ucontext->uc_mcontext, regs);
}

static inline void
signal_loongarch64_restore_ptregs(struct pt_regs *regs,
                                  const signal_loongarch64_ucontext_t *uc) {
    const signal_loongarch64_sigcontext_t *sc = &uc->uc_mcontext;

    regs->ra = sc->sc_regs[1];
    regs->tp = sc->sc_regs[2];
    regs->sp = sc->sc_regs[3];
    regs->usp = sc->sc_regs[3];
    regs->a0 = sc->sc_regs[4];
    regs->a1 = sc->sc_regs[5];
    regs->a2 = sc->sc_regs[6];
    regs->a3 = sc->sc_regs[7];
    regs->a4 = sc->sc_regs[8];
    regs->a5 = sc->sc_regs[9];
    regs->a6 = sc->sc_regs[10];
    regs->a7 = sc->sc_regs[11];
    regs->t0 = sc->sc_regs[12];
    regs->t1 = sc->sc_regs[13];
    regs->t2 = sc->sc_regs[14];
    regs->t3 = sc->sc_regs[15];
    regs->t4 = sc->sc_regs[16];
    regs->t5 = sc->sc_regs[17];
    regs->t6 = sc->sc_regs[18];
    regs->t7 = sc->sc_regs[19];
    regs->t8 = sc->sc_regs[20];
    regs->r21 = sc->sc_regs[21];
    regs->fp = sc->sc_regs[22];
    regs->s0 = sc->sc_regs[23];
    regs->s1 = sc->sc_regs[24];
    regs->s2 = sc->sc_regs[25];
    regs->s3 = sc->sc_regs[26];
    regs->s4 = sc->sc_regs[27];
    regs->s5 = sc->sc_regs[28];
    regs->s6 = sc->sc_regs[29];
    regs->s7 = sc->sc_regs[30];
    regs->s8 = sc->sc_regs[31];
    regs->pc = sc->sc_pc;
    regs->csr_prmd = LOONGARCH_PRMD_USER;
    regs->syscallno = NO_SYSCALL;
}

static bool signal_loongarch64_setup_frame(task_t *task, struct pt_regs *regs,
                                           int sig, const sigaction_t *action,
                                           const siginfo_t *info,
                                           sigset_t restore_mask) {
    struct pt_regs saved = *regs;
    bool from_syscall =
        signal_loongarch64_prepare_syscall_result(&saved, action);

    stack_t frame_altstack;
    signal_altstack_format_old(&frame_altstack, &task->signal->altstack,
                               saved.sp);

    if (!signal_ensure_user_trampoline(task))
        return false;

    uint64_t stack_top = saved.sp;
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

    if (stack_top <= sizeof(signal_loongarch64_frame_t))
        return false;

    uint64_t frame_addr = signal_loongarch64_align_down(
        stack_top - sizeof(signal_loongarch64_frame_t), 16);
    if (!frame_addr || frame_addr >= stack_top)
        return false;

    signal_loongarch64_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(&frame.info, info, sizeof(frame.info));
    if (from_syscall) {
        frame.flags |= SIGNAL_LOONGARCH64_FRAME_FROM_SYSCALL;
        frame.syscall_pc = saved.pc;
    }

    loongarch64_fpu_save(task->arch_context->fpu_ctx);
    signal_loongarch64_fill_ucontext(&frame.ucontext, &saved, restore_mask,
                                     &frame_altstack);
    signal_loongarch64_save_lsx(&frame.extcontext, task->arch_context->fpu_ctx);

    if (copy_to_user((void *)frame_addr, &frame, sizeof(frame)))
        return false;

    *regs = saved;
    regs->pc = (uint64_t)action->sa_handler;
    regs->ra = task_mm_signal_trampoline_start(task->mm);
    regs->sp = frame_addr;
    regs->usp = frame_addr;
    regs->a0 = sig;
    regs->a1 = 0;
    regs->a2 = 0;
    if (action->sa_flags & SA_SIGINFO) {
        regs->a1 = frame_addr + offsetof(signal_loongarch64_frame_t, info);
        regs->a2 = frame_addr + offsetof(signal_loongarch64_frame_t, ucontext);
    }
    regs->csr_prmd = LOONGARCH_PRMD_USER;
    regs->syscallno = NO_SYSCALL;

    return true;
}

static bool signal_arch_setup_frame(task_t *task, struct pt_regs *regs, int sig,
                                    const sigaction_t *action,
                                    const siginfo_t *info,
                                    sigset_t restore_mask) {
    return signal_loongarch64_setup_frame(task, regs, sig, action, info,
                                          restore_mask);
}

static uint64_t signal_arch_sigreturn(struct pt_regs *regs) {
    arch_disable_interrupt();

    task_t *self = current_task;
    if (!self || !regs)
        return (uint64_t)-EFAULT;

    if ((regs->sp & 0xFUL) != 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_loongarch64_frame_t frame;
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

    if (!signal_loongarch64_restore_extcontext(&frame,
                                               self->arch_context->fpu_ctx)) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_loongarch64_restore_ptregs(regs, &frame.ucontext);
    if ((frame.flags & SIGNAL_LOONGARCH64_FRAME_FROM_SYSCALL) != 0 &&
        regs->pc == frame.syscall_pc) {
        regs->pc += SIGNAL_LOONGARCH64_SYSCALL_INS_LEN;
    }
    loongarch64_fpu_restore(self->arch_context->fpu_ctx);

    spin_lock(&self->signal->sighand->siglock);
    self->signal->blocked =
        sigset_user_to_kernel(frame.ucontext.uc_sigmask.sig[0]);
    signal_altstack_store(&self->signal->altstack, &restore_altstack);
    spin_unlock(&self->signal->sighand->siglock);

    return regs->a0;
}
