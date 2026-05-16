#pragma once

#include <arch/x86_64/syscall/nr.h>

#define SIGNAL_ARCH_HAS_RESTORER_FIELD 1
#define SIGNAL_ARCH_VALIDATE_RESTORER 1
#define SIGNAL_X64_SYSCALL_INS_LEN 2
#define SIGNAL_X64_UC_SIGCONTEXT_SS 0x2
#define SIGNAL_X64_UC_STRICT_RESTORE_SS 0x4
#define SIGNAL_X64_TRAPNO_PAGE_FAULT 14
#define SIGNAL_X64_RT_SIGRETURN_TRAMPOLINE_SIZE 9U

typedef struct signal_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    void (*restorer)(void);
    sigset_t mask;
} signal_kernel_sigaction_t;

static inline uint64_t
signal_arch_user_sp_from_regs(const struct pt_regs *regs) {
    return regs->rsp;
}

static inline bool signal_arch_user_context(const struct pt_regs *regs) {
    return regs && (regs->cs & 0x3) == 0x3;
}

static const uint8_t signal_x64_rt_sigreturn_trampoline
    [SIGNAL_X64_RT_SIGRETURN_TRAMPOLINE_SIZE] = {
        0xB8, SYS_RT_SIGRETURN, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x0F, 0x0B,
};

static inline const uint8_t *
signal_arch_rt_sigreturn_trampoline(size_t *code_size) {
    if (!code_size)
        return NULL;

    *code_size = sizeof(signal_x64_rt_sigreturn_trampoline);
    return signal_x64_rt_sigreturn_trampoline;
}
