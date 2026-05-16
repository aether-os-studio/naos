#pragma once

#include <arch/aarch64/syscall/nr.h>

#define SIGNAL_ARCH_HAS_RESTORER_FIELD 1
#define SIGNAL_ARCH_VALIDATE_RESTORER 1
#define SIGNAL_AARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE 8U
#define SIGNAL_AARCH64_SYSCALL_INS_LEN 4U

typedef struct signal_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    void (*restorer)(void);
    sigset_t mask;
} signal_kernel_sigaction_t;

static inline uint64_t
signal_arch_user_sp_from_regs(const struct pt_regs *regs) {
    return regs->sp_el0;
}

static inline bool signal_arch_user_context(const struct pt_regs *regs) {
    return regs && (regs->cpsr & 0xF) == 0;
}

static const uint8_t signal_aarch64_rt_sigreturn_trampoline
    [SIGNAL_AARCH64_RT_SIGRETURN_TRAMPOLINE_SIZE] = {
        0x68, 0x11, 0x80, 0xD2, 0x01, 0x00, 0x00, 0xD4,
};

static inline const uint8_t *
signal_arch_rt_sigreturn_trampoline(size_t *code_size) {
    if (!code_size)
        return NULL;

    *code_size = sizeof(signal_aarch64_rt_sigreturn_trampoline);
    return signal_aarch64_rt_sigreturn_trampoline;
}
