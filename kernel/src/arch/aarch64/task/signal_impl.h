#pragma once

#include <libs/klibc.h>

typedef struct signal_aarch64_user_sigset {
    uint64_t __bits[16];
} signal_aarch64_user_sigset_t;

#define SIGNAL_AARCH64_RESERVED_BYTES 4096U
#define SIGNAL_AARCH64_FPSIMD_MAGIC 0x46508001U
#define SIGNAL_AARCH64_SYSCALL_INS_LEN 4U

typedef struct signal_aarch64_ctx_header {
    uint32_t magic;
    uint32_t size;
} signal_aarch64_ctx_header_t;

typedef struct signal_aarch64_fpsimd_context {
    signal_aarch64_ctx_header_t head;
    uint32_t fpsr;
    uint32_t fpcr;
    uint64_t vregs[32][2];
} __attribute__((aligned(16))) signal_aarch64_fpsimd_context_t;

typedef struct signal_aarch64_sigcontext {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint8_t __reserved[SIGNAL_AARCH64_RESERVED_BYTES]
        __attribute__((aligned(16)));
} signal_aarch64_sigcontext_t;

typedef struct signal_aarch64_ucontext {
    uint64_t uc_flags;
    struct signal_aarch64_ucontext *uc_link;
    stack_t uc_stack;
    signal_aarch64_user_sigset_t uc_sigmask;
    signal_aarch64_sigcontext_t uc_mcontext;
} signal_aarch64_ucontext_t;

typedef struct signal_aarch64_frame {
    siginfo_t info;
    signal_aarch64_ucontext_t ucontext;
} signal_aarch64_frame_t;

typedef struct signal_aarch64_frame_record {
    uint64_t fp;
    uint64_t lr;
} signal_aarch64_frame_record_t;

_Static_assert(sizeof(signal_aarch64_fpsimd_context_t) == 0x210,
               "AArch64 fpsimd_context must match the Linux ABI");
_Static_assert(offsetof(signal_aarch64_sigcontext_t, __reserved) == 0x120,
               "AArch64 sigcontext.__reserved offset must match the Linux ABI");
_Static_assert(sizeof(signal_aarch64_user_sigset_t) == 128,
               "AArch64 user sigset in ucontext must be 1024 bits");

static inline uint64_t signal_aarch64_align_down(uint64_t value,
                                                 uint64_t align) {
    return value & ~(align - 1);
}

static inline void
signal_aarch64_save_fpsimd(signal_aarch64_sigcontext_t *sigcontext,
                           const fpu_context_t *fpu_ctx) {
    memset(sigcontext->__reserved, 0, sizeof(sigcontext->__reserved));
    if (!fpu_ctx)
        return;

    signal_aarch64_fpsimd_context_t *fpsimd =
        (signal_aarch64_fpsimd_context_t *)sigcontext->__reserved;
    fpsimd->head.magic = SIGNAL_AARCH64_FPSIMD_MAGIC;
    fpsimd->head.size = sizeof(*fpsimd);
    fpsimd->fpsr = (uint32_t)fpu_ctx->fpsr;
    fpsimd->fpcr = (uint32_t)fpu_ctx->fpcr;
    memcpy(fpsimd->vregs, fpu_ctx->q, sizeof(fpsimd->vregs));
}

static bool
signal_aarch64_restore_fpsimd(const signal_aarch64_sigcontext_t *sigcontext,
                              fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return true;

    aarch64_fpu_state_init(fpu_ctx);

    const uint8_t *cursor = sigcontext->__reserved;
    size_t remaining = sizeof(sigcontext->__reserved);
    bool fpsimd_seen = false;

    while (remaining >= sizeof(signal_aarch64_ctx_header_t)) {
        const signal_aarch64_ctx_header_t *head =
            (const signal_aarch64_ctx_header_t *)cursor;

        if (head->magic == 0 && head->size == 0)
            return true;

        if ((head->size & 0xFUL) != 0 ||
            head->size < sizeof(signal_aarch64_ctx_header_t) ||
            head->size > remaining) {
            return false;
        }

        if (head->magic == SIGNAL_AARCH64_FPSIMD_MAGIC) {
            if (fpsimd_seen ||
                head->size != sizeof(signal_aarch64_fpsimd_context_t)) {
                return false;
            }

            const signal_aarch64_fpsimd_context_t *fpsimd =
                (const signal_aarch64_fpsimd_context_t *)cursor;
            fpu_ctx->fpsr = fpsimd->fpsr;
            fpu_ctx->fpcr = fpsimd->fpcr;
            memcpy(fpu_ctx->q, fpsimd->vregs, sizeof(fpsimd->vregs));
            fpsimd_seen = true;
        }

        cursor += head->size;
        remaining -= head->size;
    }

    return false;
}

static inline void
signal_aarch64_prepare_syscall_result(struct pt_regs *saved,
                                      const sigaction_t *action) {
    if (!saved || !action || saved->syscallno == NO_SYSCALL ||
        saved->syscallno == SYS_RT_SIGRETURN)
        return;

    int64_t retval = (int64_t)saved->x0;
    if (retval >= 0)
        return;

    switch (-retval) {
    case ERESTARTNOHAND:
    case ERESTART_RESTARTBLOCK:
        saved->x0 = (uint64_t)-EINTR;
        break;
    case ERESTARTSYS:
        if ((action->sa_flags & SA_RESTART) == 0) {
            saved->x0 = (uint64_t)-EINTR;
            break;
        }
        __attribute__((fallthrough));
    case ERESTARTNOINTR:
        saved->x0 = saved->origin_x0;
        if (saved->pc >= SIGNAL_AARCH64_SYSCALL_INS_LEN)
            saved->pc -= SIGNAL_AARCH64_SYSCALL_INS_LEN;
        break;
    default:
        return;
    }
}

static inline void
signal_aarch64_fill_ucontext(signal_aarch64_ucontext_t *ucontext,
                             const struct pt_regs *regs, sigset_t blocked_mask,
                             const stack_t *altstack, const siginfo_t *info,
                             const fpu_context_t *fpu_ctx) {
    memset(ucontext, 0, sizeof(*ucontext));

    if (altstack)
        ucontext->uc_stack = *altstack;
    ucontext->uc_sigmask.__bits[0] = sigset_kernel_to_user(blocked_mask);

    if (info && info->si_signo == SIGSEGV)
        ucontext->uc_mcontext.fault_address =
            (uint64_t)info->_sifields._sigfault._addr;

    ucontext->uc_mcontext.regs[0] = regs->x0;
    ucontext->uc_mcontext.regs[1] = regs->x1;
    ucontext->uc_mcontext.regs[2] = regs->x2;
    ucontext->uc_mcontext.regs[3] = regs->x3;
    ucontext->uc_mcontext.regs[4] = regs->x4;
    ucontext->uc_mcontext.regs[5] = regs->x5;
    ucontext->uc_mcontext.regs[6] = regs->x6;
    ucontext->uc_mcontext.regs[7] = regs->x7;
    ucontext->uc_mcontext.regs[8] = regs->x8;
    ucontext->uc_mcontext.regs[9] = regs->x9;
    ucontext->uc_mcontext.regs[10] = regs->x10;
    ucontext->uc_mcontext.regs[11] = regs->x11;
    ucontext->uc_mcontext.regs[12] = regs->x12;
    ucontext->uc_mcontext.regs[13] = regs->x13;
    ucontext->uc_mcontext.regs[14] = regs->x14;
    ucontext->uc_mcontext.regs[15] = regs->x15;
    ucontext->uc_mcontext.regs[16] = regs->x16;
    ucontext->uc_mcontext.regs[17] = regs->x17;
    ucontext->uc_mcontext.regs[18] = regs->x18;
    ucontext->uc_mcontext.regs[19] = regs->x19;
    ucontext->uc_mcontext.regs[20] = regs->x20;
    ucontext->uc_mcontext.regs[21] = regs->x21;
    ucontext->uc_mcontext.regs[22] = regs->x22;
    ucontext->uc_mcontext.regs[23] = regs->x23;
    ucontext->uc_mcontext.regs[24] = regs->x24;
    ucontext->uc_mcontext.regs[25] = regs->x25;
    ucontext->uc_mcontext.regs[26] = regs->x26;
    ucontext->uc_mcontext.regs[27] = regs->x27;
    ucontext->uc_mcontext.regs[28] = regs->x28;
    ucontext->uc_mcontext.regs[29] = regs->x29;
    ucontext->uc_mcontext.regs[30] = regs->x30;
    ucontext->uc_mcontext.sp = regs->sp_el0;
    ucontext->uc_mcontext.pc = regs->pc;
    ucontext->uc_mcontext.pstate = regs->cpsr;
    signal_aarch64_save_fpsimd(&ucontext->uc_mcontext, fpu_ctx);
}

static bool
signal_aarch64_restore_ptregs(struct pt_regs *regs,
                              const signal_aarch64_ucontext_t *ucontext,
                              fpu_context_t *fpu_ctx) {
    regs->x0 = ucontext->uc_mcontext.regs[0];
    regs->x1 = ucontext->uc_mcontext.regs[1];
    regs->x2 = ucontext->uc_mcontext.regs[2];
    regs->x3 = ucontext->uc_mcontext.regs[3];
    regs->x4 = ucontext->uc_mcontext.regs[4];
    regs->x5 = ucontext->uc_mcontext.regs[5];
    regs->x6 = ucontext->uc_mcontext.regs[6];
    regs->x7 = ucontext->uc_mcontext.regs[7];
    regs->x8 = ucontext->uc_mcontext.regs[8];
    regs->x9 = ucontext->uc_mcontext.regs[9];
    regs->x10 = ucontext->uc_mcontext.regs[10];
    regs->x11 = ucontext->uc_mcontext.regs[11];
    regs->x12 = ucontext->uc_mcontext.regs[12];
    regs->x13 = ucontext->uc_mcontext.regs[13];
    regs->x14 = ucontext->uc_mcontext.regs[14];
    regs->x15 = ucontext->uc_mcontext.regs[15];
    regs->x16 = ucontext->uc_mcontext.regs[16];
    regs->x17 = ucontext->uc_mcontext.regs[17];
    regs->x18 = ucontext->uc_mcontext.regs[18];
    regs->x19 = ucontext->uc_mcontext.regs[19];
    regs->x20 = ucontext->uc_mcontext.regs[20];
    regs->x21 = ucontext->uc_mcontext.regs[21];
    regs->x22 = ucontext->uc_mcontext.regs[22];
    regs->x23 = ucontext->uc_mcontext.regs[23];
    regs->x24 = ucontext->uc_mcontext.regs[24];
    regs->x25 = ucontext->uc_mcontext.regs[25];
    regs->x26 = ucontext->uc_mcontext.regs[26];
    regs->x27 = ucontext->uc_mcontext.regs[27];
    regs->x28 = ucontext->uc_mcontext.regs[28];
    regs->x29 = ucontext->uc_mcontext.regs[29];
    regs->x30 = ucontext->uc_mcontext.regs[30];
    regs->sp_el0 = ucontext->uc_mcontext.sp;
    regs->pc = ucontext->uc_mcontext.pc;
    regs->cpsr = ucontext->uc_mcontext.pstate;
    regs->origin_x0 = regs->x0;
    regs->syscallno = NO_SYSCALL;

    if ((regs->cpsr & 0xF) != 0)
        regs->cpsr &= ~0xFULL;

    return signal_aarch64_restore_fpsimd(&ucontext->uc_mcontext, fpu_ctx);
}

static bool signal_aarch64_setup_frame(task_t *task, struct pt_regs *regs,
                                       int sig, const sigaction_t *action,
                                       const siginfo_t *info,
                                       sigset_t restore_mask) {
    struct pt_regs saved = *regs;
    signal_aarch64_prepare_syscall_result(&saved, action);

    stack_t frame_altstack;
    signal_altstack_format_old(&frame_altstack, &task->signal->altstack,
                               saved.sp_el0);

    uint64_t stack_top = saved.sp_el0;
    uint64_t trampoline_bytes = 0;
    bool use_kernel_restorer =
        !(action->sa_flags & SA_RESTORER) || !action->sa_restorer;
    if (use_kernel_restorer && !signal_ensure_user_trampoline(task))
        return false;
    bool use_altstack =
        (action->sa_flags & SA_ONSTACK) &&
        signal_altstack_config_enabled(&task->signal->altstack) &&
        !signal_altstack_contains_sp(&task->signal->altstack, saved.sp_el0);
    if (use_altstack) {
        stack_top = signal_stack_base(&task->signal->altstack) +
                    task->signal->altstack.ss_size;
        if (task->signal->altstack.ss_flags & SS_AUTODISARM)
            signal_altstack_disable(&task->signal->altstack);
    }

    if (stack_top <= sizeof(signal_aarch64_frame_t) +
                         sizeof(signal_aarch64_frame_record_t) +
                         trampoline_bytes)
        return false;

    uint64_t frame_record_addr = signal_aarch64_align_down(
        stack_top - sizeof(signal_aarch64_frame_record_t), 16);
    if (!frame_record_addr)
        return false;

    uint64_t frame_addr = signal_aarch64_align_down(
        frame_record_addr - sizeof(signal_aarch64_frame_t), 16);
    if (!frame_addr || frame_addr >= frame_record_addr)
        return false;

    signal_aarch64_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(&frame.info, info, sizeof(frame.info));
    aarch64_fpu_save(task->arch_context->fpu_ctx);
    signal_aarch64_fill_ucontext(&frame.ucontext, &saved, restore_mask,
                                 &frame_altstack, info,
                                 task->arch_context->fpu_ctx);

    signal_aarch64_frame_record_t frame_record = {
        .fp = saved.x29,
        .lr = saved.x30,
    };

    if (copy_to_user((void *)frame_addr, &frame, sizeof(frame)) ||
        copy_to_user((void *)frame_record_addr, &frame_record,
                     sizeof(frame_record))) {
        return false;
    }

    memset(regs, 0, sizeof(*regs));
    regs->pc = (uint64_t)action->sa_handler;
    regs->sp_el0 = frame_addr;
    regs->origin_x0 = saved.origin_x0;
    regs->syscallno = NO_SYSCALL;
    regs->x0 = sig;
    if (action->sa_flags & SA_SIGINFO) {
        regs->x1 = frame_addr + offsetof(signal_aarch64_frame_t, info);
        regs->x2 = frame_addr + offsetof(signal_aarch64_frame_t, ucontext);
    }
    regs->x29 = frame_record_addr;
    regs->x30 = use_kernel_restorer ? task_mm_signal_trampoline_start(task->mm)
                                    : (uint64_t)action->sa_restorer;
    regs->cpsr = 0x80000300;

    return true;
}

static bool signal_arch_setup_frame(task_t *task, struct pt_regs *regs, int sig,
                                    const sigaction_t *action,
                                    const siginfo_t *info,
                                    sigset_t restore_mask) {
    return signal_aarch64_setup_frame(task, regs, sig, action, info,
                                      restore_mask);
}

static uint64_t signal_arch_sigreturn(struct pt_regs *regs) {
    arch_disable_interrupt();

    task_t *self = current_task;
    if (!self || !regs) {
        return (uint64_t)-EFAULT;
    }

    if ((regs->sp_el0 & 0xFUL) != 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    signal_aarch64_frame_t frame;
    if (copy_from_user(&frame, (void *)regs->sp_el0, sizeof(frame))) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    stack_t restore_altstack = frame.ucontext.uc_stack;
    restore_altstack.ss_flags &= ~SS_ONSTACK;
    if (signal_altstack_validate_new(&restore_altstack) < 0) {
        task_exit(128 + SIGSEGV);
        return 0;
    }

    if (!signal_aarch64_restore_ptregs(regs, &frame.ucontext,
                                       self->arch_context->fpu_ctx)) {
        task_exit(128 + SIGSEGV);
        return 0;
    }
    aarch64_fpu_restore(self->arch_context->fpu_ctx);

    spin_lock(&self->signal->sighand->siglock);
    self->signal->blocked =
        sigset_user_to_kernel(frame.ucontext.uc_sigmask.__bits[0]);
    signal_altstack_store(&self->signal->altstack, &restore_altstack);
    spin_unlock(&self->signal->sighand->siglock);

    return regs->x0;
}
