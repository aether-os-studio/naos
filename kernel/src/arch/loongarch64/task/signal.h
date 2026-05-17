#pragma once

#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/syscall/nr.h>

#define SIGNAL_ARCH_HAS_RESTORER_FIELD 0
#define SIGNAL_ARCH_VALIDATE_RESTORER 0
#define SIGNAL_LOONGARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE 8U
#define SIGNAL_LOONGARCH64_SYSCALL_INS_LEN 4U
#define SIGNAL_LOONGARCH64_FRAME_FROM_SYSCALL 1U

typedef struct signal_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    sigset_t mask;
} signal_kernel_sigaction_t;

_Static_assert(sizeof(signal_kernel_sigaction_t) == 24,
               "LoongArch64 sigaction must match Linux asm-generic ABI");

static inline uint64_t
signal_arch_user_sp_from_regs(const struct pt_regs *regs) {
    return regs->sp;
}

static inline bool signal_arch_user_context(const struct pt_regs *regs) {
    return regs &&
           ((regs->csr_prmd & LOONGARCH_PRMD_PPLV_MASK) == LOONGARCH_PLV_USER);
}

static const uint8_t signal_loongarch64_rt_sigreturn_trampoline
    [SIGNAL_LOONGARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE] = {
        0x0b, 0x2c, 0xc2, 0x02, 0x00, 0x00, 0x2b, 0x00,
};

static inline const uint8_t *
signal_arch_rt_sigreturn_trampoline(size_t *code_size) {
    if (!code_size)
        return NULL;

    *code_size = sizeof(signal_loongarch64_rt_sigreturn_trampoline);
    return signal_loongarch64_rt_sigreturn_trampoline;
}
