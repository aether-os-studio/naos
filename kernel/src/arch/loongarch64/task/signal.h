#pragma once

#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/syscall/nr.h>

#define SIGNAL_ARCH_HAS_RESTORER_FIELD 0
#define SIGNAL_ARCH_VALIDATE_RESTORER 0
#define SIGNAL_LOONGARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE 0U

typedef struct signal_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    sigset_t mask;
    void *unused;
} signal_kernel_sigaction_t;

static inline uint64_t
signal_arch_user_sp_from_regs(const struct pt_regs *regs) {
    return regs->usp;
}

static inline bool signal_arch_user_context(const struct pt_regs *regs) {
    return regs &&
           ((regs->csr_prmd & LOONGARCH_PRMD_PPLV_MASK) == LOONGARCH_PLV_USER);
}

static inline const uint8_t *
signal_arch_rt_sigreturn_trampoline(size_t *code_size) {
    if (!code_size)
        return NULL;

    *code_size = SIGNAL_LOONGARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE;
    return NULL;
}
